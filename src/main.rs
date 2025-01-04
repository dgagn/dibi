use dibi::{
    connection::{Connection, ConnectionOption},
    ssl::{TlsMode, TlsOptions},
    stream::StreamType,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let password = std::env::var("MYSQL_PASSWORD").unwrap();
    let tls_opts = TlsOptions {
        mode: TlsMode::Required,
        domain: Some("localhost"),
        ..Default::default()
    };
    let options = ConnectionOption {
        host: "127.0.0.1:3306",
        stream_type: StreamType::Tcp,
        tls: tls_opts,
        username: "ovior",
        password: &password,
    };
    let connection = Connection::connect(&options).await.unwrap();

    println!("Connected to MySQL server");
}
