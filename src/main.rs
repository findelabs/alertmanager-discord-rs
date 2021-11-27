use axum::{
	handler::Handler,
    extract::Extension,
	http::StatusCode,
	response::{IntoResponse},
    http::{Request, Response},
    routing::{get, post},
    AddExtensionLayer, Router,
    Json
};
use hyper_tls::HttpsConnector;
use hyper::{client::HttpConnector, Body, Method};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use std::{net::SocketAddr};
use serde_json::{Value, json};
use clap::{crate_version, App, Arg};
use env_logger::{Builder, Target};
use log::LevelFilter;
use std::io::Write;
use chrono::Local;
use std::sync::Arc;

struct State {
    webhook: String
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
                .takes_value(true)
        )
        .arg(
            Arg::with_name("webhook")
                .short("w")
                .long("webhook")
                .required(true)
                .value_name("DISCORD_WEBHOOK")
                .help("Discord Webhook Endpoint")
                .takes_value(true)
        )
        .get_matches();

    // Initialize log Builder
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{{\"date\": \"{}\", \"level\": \"{}\", {}}}",
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

    let shared_state = Arc::new(State { webhook: opts.value_of("webhook").unwrap().to_string() });

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
	log::info!("hit /health");
    Json(json!({ "msg": "Healthy"}))
}

async fn echo(Json(payload): Json<Value>) -> Json<Value> {
	log::info!("Returning /echo");
    Json(payload)
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}

async fn handler(Extension(client): Extension<HttpsClient>, Extension(state): Extension<Arc<State>>, Json(payload): Json<Value>) -> Response<Body> {

	let body = generate_body(payload).await;

	log::info!("{}", &body);

	let mut req = Request::builder()
        .method(Method::POST)
        .uri(&state.webhook)
	    .body(Body::from(body.to_string()))
	    .expect("request builder");
    req.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));


    client.request(req).await.unwrap()
}

async fn generate_body(payload: Value) -> Value {
    let mut card = json!({
        "username": "AlertManager",
        "content": "",
        "embeds": [
          {
            "title": "Title",
            "url": "https://google.com/",
            "description": "Text message. You can use Markdown here. *Italic* **bold** __underline__ ~~strikeout~~ [hyperlink](https://google.com) `code`",
            "color": 15258703,
            "fields": [
              {
                "name": "Text",
                "value": "More text",
                "inline": true
              }
            ]
          }
        ]
    });

	if payload["commonAnnotations"]["description"].is_string() {
		card["content"] = payload["commonAnnotations"]["description"].clone();
	}

	card
}

