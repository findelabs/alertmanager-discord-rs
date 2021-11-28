use axum::{
    extract::Extension,
    handler::Handler,
    http::StatusCode,
    http::{Request, Response},
    response::IntoResponse,
    routing::{get, post},
    AddExtensionLayer, Json, Router,
};
use chrono::Local;
use clap::{crate_version, App, Arg};
use env_logger::{Builder, Target};
use hyper::header::{HeaderValue, CONTENT_TYPE};
use hyper::{client::HttpConnector, Body, Method};
use hyper_tls::HttpsConnector;
use log::LevelFilter;
use serde_json::{json, Value};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

struct State {
    webhook: String,
}

type HttpsClient = hyper::client::Client<HttpsConnector<HttpConnector>, Body>;

#[tokio::main]
async fn main() {
    let opts = App::new("alertmanager-discord-rust")
        .version(crate_version!())
        .author("Daniel F. <Verticaleap>")
        .about("alertmanager-discord-rust")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .help("Set port to listen on")
                .required(false)
                .env("LISTEN_PORT")
                .default_value("8080")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("webhook")
                .short("w")
                .long("webhook")
                .required(true)
                .value_name("DISCORD_WEBHOOK")
                .help("Discord Webhook Endpoint")
                .takes_value(true),
        )
        .get_matches();

    // Initialize log Builder
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{{\"date\": \"{}\", \"level\": \"{}\", \"log\": {}}}",
                Local::now().format("%Y-%m-%dT%H:%M:%S:%f"),
                record.level(),
                record.args()
            )
        })
        .target(Target::Stdout)
        .filter_level(LevelFilter::Error)
        .parse_default_env()
        .init();

    // Set port
    let port: u16 = opts.value_of("port").unwrap().parse().unwrap_or_else(|_| {
        eprintln!("specified port isn't in a valid range, setting to 8080");
        8080
    });

    let shared_state = Arc::new(State {
        webhook: opts.value_of("webhook").unwrap().to_string(),
    });

    let https = HttpsConnector::new();
    let client = hyper::Client::builder().build::<_, hyper::Body>(https);

    let app = Router::new()
        .route("/post", post(handler))
        .route("/health", get(health))
        .route("/echo", post(echo))
        .layer(AddExtensionLayer::new(client))
        .layer(AddExtensionLayer::new(shared_state));

    // add a fallback service for handling routes to unknown paths
    let app = app.fallback(handler_404.into_service());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("Listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn health() -> Json<Value> {
    log::info!("\"hit /health\"");
    Json(json!({ "msg": "Healthy"}))
}

async fn echo(Json(payload): Json<Value>) -> Json<Value> {
    log::info!("\"Returning /echo\"");
    Json(payload)
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}

async fn handler(
    Extension(client): Extension<HttpsClient>,
    Extension(state): Extension<Arc<State>>,
    Json(payload): Json<Value>,
) -> Response<Body> {
    let body = generate_body(payload).await;

    log::info!("{}", &body);

    let mut req = Request::builder()
        .method(Method::POST)
        .uri(&state.webhook)
        .body(Body::from(body.to_string()))
        .expect("request builder");

    req.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    client.request(req).await.unwrap()
}

async fn generate_body(payload: Value) -> Value {
    let mut card = json!({
        "content": "",
        "embeds": []
    });

    // Set content of main card
    card["content"] = match payload["commonAnnotations"]["summary"].is_string() {
        true => payload["commonAnnotations"]["summary"].clone(),
        false => json!("")
    };

    // Create embeds sub doc
    let mut embeds = json!([{
        "title": "",
        "url": "",
        "color": 0x95A5A6,
        "fields": []
    }]);

//    // Get count of alerts
//    let alert_count = match payload["alerts"].as_array() {
//        Some(alerts) => alerts.len(),
//        None => 0,
//    };

    // Set card title
    let title = format!(
        "[{}] {}",
        payload["status"].as_str().expect("status").to_uppercase(),
        payload["commonLabels"]["alertname"]
            .as_str()
            .expect("alertname")
    );

    // This needs to go into the embed title
    embeds[0]["title"] = json!(title);

    // Set prometheus url in embed doc
    if payload["externalURL"].is_string() {
        embeds[0]["url"] = payload["externalURL"].clone();
    }

    // Set embed doc color
    embeds[0]["color"] = match payload["status"].as_str() {
        Some("firing") => json!(0x992D22),
        Some("resolved") => json!(0x2ECC71),
        _ => json!(0x95A5A6),
    };

    // Gather all alerts to fields array for embed doc
    let mut fields = Vec::new();
    if let Some(alerts) = payload["alerts"].as_array() {
        for alert in alerts {
            log::info!("\"Processing alert {}\"", alert["labels"]["alertname"].as_str().expect("missing alertname"));

            let _instance = match alert["labels"]["instance"].is_string() {
                true => alert["labels"]["instance"].as_str().expect("alert instance"),
                false => "unknown",
            };

            let alertname = match alert["labels"]["alertname"].is_string() {
                true => alert["labels"]["alertname"].clone(),
                false => json!("missing alertname")
            };

            //let name = format!("instance: {}", instance);
            let value = alert["annotations"]["description"].clone();
            let field = json!({"name": alertname, "value": value});
            fields.push(field);
        }
    }

    // Add fields to embeds
    embeds[0]["fields"] = json!(fields);

    // Build out main card
    card["embeds"] = json!(embeds);

    card
}
