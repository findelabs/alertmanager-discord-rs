use axum::{
    extract::Extension,
    http::{uri::Uri, Request, Response},
    routing::{get, post},
    AddExtensionLayer, Router,
    Json
};
use hyper::{client::HttpConnector, Body};
use std::{convert::TryFrom, net::SocketAddr};
use serde::{Serialize};
use serde_json::{Value, json};
use clap::{crate_version, App, Arg};
use env_logger::{Builder, Target};
use log::LevelFilter;
use std::io::Write;
use chrono::Local;

#[derive(Serialize)]
struct Message {
    msg: String
}

type Client = hyper::client::Client<HttpConnector, Body>;

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
        .get_matches();

    // Initialize log Builder
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{{\"date\": \"{}\", \"level\": \"{}\", \"message\": \"{}\"}}",
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

    let client = Client::new();

    let app = Router::new()
        .route("/", get(handler))
        .route("/health", get(health))
        .route("/echo", post(echo))
        .layer(AddExtensionLayer::new(client));

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

async fn handler(Extension(client): Extension<Client>, mut req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);

    let uri = format!("http://127.0.0.1:3000{}", path_query);
    *req.uri_mut() = Uri::try_from(uri).unwrap();
    client.request(req).await.unwrap()
}

