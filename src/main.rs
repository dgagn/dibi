use dibi::{
    connection::{Connection, ConnectionOption},
    ssl::{TlsMode, TlsOptions},
    stream::StreamType,
};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let password = std::env::var("MYSQL_PASSWORD").unwrap();
    let tls_opts = TlsOptions {
        mode: TlsMode::Disable,
        ..Default::default()
    };
    let options = ConnectionOption {
        host: "127.0.0.1:3306",
        stream_type: StreamType::Tcp,
        tls: tls_opts,
        username: "oviora",
        password: password.as_bytes(),
        database: None,
    };
    let mut connection = Connection::connect(&options).await.unwrap();

    connection.ping().await.unwrap();

    connection.ping().await.unwrap();

    println!("Connected to MySQL server");
}
