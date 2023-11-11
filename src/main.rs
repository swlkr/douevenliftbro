use enum_router::Routes;
use maud::{html, Markup};

fn main() {
    #[cfg(feature = "backend")]
    backend::main()
}

pub fn count(count: i64) -> Markup {
    html! {
        #counter { "count:" (count) }
    }
}

pub fn counter() -> Markup {
    html! {
        (count(0))
        button hx-get=(Route::Inc) hx-swap="outerHTML" hx-target="#counter" { "add" }
        button hx-get=(Route::Dec) hx-swap="outerHTML" hx-target="#counter" { "subtract" }
    }
}

#[derive(Routes)]
enum Route {
    #[route("/")]
    Root,
    #[route("/frontend/*file")]
    FileRequested,
    #[route("/frontend/inc")]
    Inc,
    #[route("/frontend/dec")]
    Dec,
    #[route("/frontend/404")]
    NotFound,
}

#[cfg(feature = "frontend")]
mod frontend {
    use crate::{count, html, Markup, Route};
    use serde::{Deserialize, Serialize};
    use std::sync::{Mutex, MutexGuard};
    static COUNTER: Mutex<i64> = Mutex::new(0);

    fn dec(_request: &Request) -> Markup {
        *(COUNTER.lock().unwrap()) -= 1;

        count(*COUNTER.lock().unwrap())
    }

    fn inc(_request: &Request) -> Markup {
        *(COUNTER.lock().unwrap()) += 1;

        count(*COUNTER.lock().unwrap())
    }

    fn not_found(_request: &Request) -> Markup {
        html! { "not found" }
    }

    fn route(request: &Request) -> Markup {
        let route = Route::from(request.path());
        let handler = match route {
            Route::Inc => inc,
            Route::Dec => dec,
            Route::NotFound => not_found,
            _ => not_found,
        };

        handler(request)
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct Request {
        #[serde(with = "http_serde::method")]
        method: http::method::Method,
        #[serde(with = "http_serde::uri")]
        url: http::Uri,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl Request {
        fn path(&self) -> &str {
            self.url.path_and_query().unwrap().as_str()
        }
    }

    struct RoutingState {
        request: Option<Vec<u8>>,
        response: Option<String>,
    }

    static ROUTING_STATE: Mutex<RoutingState> = Mutex::new(RoutingState {
        request: None,
        response: None,
    });

    fn get_routing_state() -> MutexGuard<'static, RoutingState> {
        ROUTING_STATE.lock().unwrap()
    }

    #[no_mangle]
    pub extern "C" fn allocate_request(size: usize) -> *mut u8 {
        let mut rs = get_routing_state();
        rs.request = Some(vec![0; size]);
        rs.request.as_mut().unwrap().as_mut_ptr()
    }

    #[no_mangle]
    pub extern "C" fn fetch() -> usize {
        let mut rs = get_routing_state();
        let request_string = if let Some(ref request) = rs.request {
            String::from_utf8(request.clone()).unwrap()
        } else {
            String::from("{}")
        };
        rs.response = match serde_json::from_str(&request_string) {
            Ok(request) => Some(route(&request).into()),
            Err(_) => Some("Failed to parse request string from service worker js".to_string()),
        };
        0
    }

    #[no_mangle]
    pub extern "C" fn response_ptr() -> *const u8 {
        let rs = get_routing_state();

        if let Some(r) = &rs.response {
            r.as_ptr()
        } else {
            0 as *const u8
        }
    }

    #[no_mangle]
    pub extern "C" fn response_len() -> usize {
        let rs = get_routing_state();

        if let Some(r) = &rs.response {
            r.len()
        } else {
            0
        }
    }

    #[no_mangle]
    pub extern "C" fn stop() -> usize {
        0
    }
}

#[cfg(feature = "backend")]
pub mod backend {
    use axum::{
        http::{
            header::{CACHE_CONTROL, CONTENT_TYPE},
            Uri,
        },
        response::{IntoResponse, Response},
        routing::get,
        Router, Server,
    };
    use maud::{html, Markup, DOCTYPE};

    use crate::{counter, Route};

    #[tokio::main]
    pub async fn main() {
        let app = routes();
        let addr = "127.0.0.1:9006".parse().unwrap();
        println!("Listening on localhost:9006");
        Server::bind(&addr)
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    fn routes() -> Router {
        Router::new()
            .route(&Route::Root.to_string(), get(root))
            .route(&Route::FileRequested.to_string(), get(file_requested))
    }

    fn head() -> Markup {
        html! {
            head {
                script src="/frontend/htmx.js" {}
                script src="/frontend/json-enc.js" {}
                script src="/frontend/app.js" {}
            }
        }
    }

    async fn root() -> Markup {
        html! {
            (DOCTYPE)
            html {
                (head())
                body {
                    (counter())
                }
            }
        }
    }

    async fn file_requested(uri: Uri) -> impl IntoResponse {
        StaticFile(uri.path().to_string())
    }

    #[derive(rust_embed::RustEmbed)]
    #[folder = "frontend"]
    #[prefix = "/frontend/"]
    pub struct Files;

    pub struct StaticFile<T>(pub T);

    impl<T> StaticFile<T>
    where
        T: Into<String>,
    {
        fn maybe_response(self) -> Result<Response> {
            let path: String = self.0.into();
            let mut builder = Response::builder();
            if path.ends_with("sw.js") {
                builder = builder.header("Service-Worker-Allowed", "/");
            }
            let asset = Files::get(path.as_str()).ok_or(Error::NotFound)?;
            let body = axum::body::boxed(axum::body::Full::from(asset.data));
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let response = builder
                .header(CONTENT_TYPE, mime.as_ref())
                .header(CACHE_CONTROL, "public, max-age=604800")
                .body(body)
                .map_err(|_| Error::NotFound)?;
            Ok(response)
        }
    }

    impl<T> IntoResponse for StaticFile<T>
    where
        T: Into<String>,
    {
        fn into_response(self) -> Response {
            self.maybe_response()
                .unwrap_or(Error::NotFound.into_response())
        }
    }

    impl IntoResponse for Error {
        fn into_response(self) -> Response {
            let (status, error_message) = match self {
                Error::NotFound | Error::RowNotFound => {
                    (axum::http::StatusCode::NOT_FOUND, format!("{self}"))
                }
                _ => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                ),
            };
            let body = axum::response::Html(error_message);

            (status, body).into_response()
        }
    }

    #[allow(unused)]
    #[justerror::Error]
    #[derive(Clone)]
    enum Error {
        NotFound,
        InternalServer,
        RowNotFound,
    }

    type Result<T> = std::result::Result<T, Error>;
}
