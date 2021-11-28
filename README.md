# Alertmanager-discord-rs

A simple alertmanager -> discord proxy written in rust.

### Installation

Once rust has been [installed](https://www.rust-lang.org/tools/install), simply run:
```
cargo install --git https://github.com/findelabs/alertmanager-discord-rs.git
```

### Usage

```
alertmanager-discord-rust 0.1.0
Daniel F. <Verticaleap>
alertmanager-discord-rust

USAGE:
    alertmanager-discord-rust [OPTIONS] --webhook <DISCORD_WEBHOOK>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -p, --port <port>                  Set port to listen on [env: LISTEN_PORT=]  [default: 8080]
    -w, --webhook <DISCORD_WEBHOOK>    Discord Webhook Endpoint
```
