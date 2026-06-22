use axum::{Router, response::Redirect};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let static_files = ServeDir::new("../web");

    let app = Router::new()
        .route("/", axum::routing::get(|| async {
            Redirect::to("/sharing.html")
        }))
        .fallback_service(static_files);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000")
        .await
        .unwrap();

    println!("Server running at http://127.0.0.1:4000");

    axum::serve(listener, app).await.unwrap();
}