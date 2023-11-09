use axum::{routing::get, Router, Server};
use maud::{html, Markup, DOCTYPE};

#[tokio::main]
async fn main() {
    let app = routes();
    let addr = "127.0.0.1:9006".parse().unwrap();
    println!("Listening on localhost:9006");
    Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

enum Route {
    Root,
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Route::Root => "/",
        })
    }
}

fn routes() -> Router {
    Router::new().route(&Route::Root.to_string(), get(root))
}

async fn root() -> Markup {
    html! {
        (DOCTYPE)
        html {
            head {

            }
            body {
                h1 class="" { "hello world" }
            }
        }
    }
}
