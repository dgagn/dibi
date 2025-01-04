use dibi::{
    connection::{Connection, ConnectionOption},
    ssl::{TlsMode, TlsOptions},
    stream::StreamType,
};

#[tokio::main]
async fn main() {
    let tls_opts = TlsOptions {
        mode: TlsMode::Required,
        domain: Some("localhost"),
        ..Default::default()
    };
    let options = ConnectionOption {
        host: "127.0.0.1:3306",
        stream_type: StreamType::Tcp,
        tls: tls_opts,
    };
    let connection = Connection::connect(&options).await.unwrap();

    println!("Connected to MySQL server");
}
