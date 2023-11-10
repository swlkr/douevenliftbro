fn main() {
    #[cfg(feature = "backend")]
    backend::main()
}

#[cfg(feature = "frontend")]
mod frontend {
    use matchit::{Params, Router};
    use maud::{html, Markup};
    use serde::{Deserialize, Serialize};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    type Handler = fn(&Params, &Request) -> String;

    static COUNTER: Mutex<u64> = Mutex::new(0);

    fn main() -> Result<()> {
        Ok(())
    }

    fn about_clicked(url: &str) -> Markup {
        *(COUNTER.lock().unwrap()) += 1;

        about_clicked_display(url)
    }

    fn about_clicked_display(url: &str) -> Markup {
        html! {
            <div>
                "Hey <b>Darrly</b>, this html is generated from Rust WASM using"
                " a service worker that intercepts http calls and returns HTML for "
                { url }
                <br />
                <p>"Clicked count: " { *(COUNTER.lock().unwrap()) }</p>
            </div>
        }
    }

    fn routes() -> Result<Router<Handler>> {
        let mut router: Router<Handler> = Router::new();
        router.insert("/;clicked", |_, r| about_clicked(r.path()).into())?;
        Ok(router);
    }

    fn handle_request(request: &Request) -> String {
        let router = routes();
        let path = request.path().trim_start_matches("/wasm-service");
        let (handler, params) = match router.at(path) {
            Ok(ok) => (ok.value, ok.params),
            Err(matchit::MatchError::NotFound) => return html! { <p>"Not found"</p> },
            Err(e) => return html! { <p>"Error matching request handler: " {e}</p> },
        };
        handler(&params, request)
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
            Ok(request) => Some(handle_request(&request)),
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

    #[allow(unused)]
    #[justerror::Error]
    #[derive(Clone)]
    enum Error {
        RouteInsert(#[from] matchit::InsertError),
    }

    type Result<T> = std::result::Result<T, Error>;
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

    enum Route {
        Root,
        FileRequested,
    }

    impl std::fmt::Display for Route {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Route::Root => "/",
                Route::FileRequested => "/pub/*file",
            })
        }
    }

    fn routes() -> Router {
        Router::new()
            .route(&Route::Root.to_string(), get(root))
            .route(&Route::FileRequested.to_string(), get(file_requested))
    }

    async fn root() -> Markup {
        html! {
            (DOCTYPE)
            html {
                head {
                    script src="./pub/htmx.js" {}
                    script src="./pub/json-enc.js" {}
                    script src="./pub/app.js" {}
                }
                body {
                    h1 class="" { "hello world" }
                }
            }
        }
    }

    async fn file_requested(uri: Uri) -> impl IntoResponse {
        let mut path = uri.path().trim_start_matches('/').to_string();
        if path.starts_with("pub/") {
            path = path.replace("pub/", "");
        }
        StaticFile(path)
    }

    #[derive(rust_embed::RustEmbed)]
    #[folder = "pub"]
    pub struct Files;

    pub struct StaticFile<T>(pub T);

    impl<T> StaticFile<T>
    where
        T: Into<String>,
    {
        fn maybe_response(self) -> Result<Response> {
            let path = self.0.into();
            let asset = Files::get(path.as_str()).ok_or(Error::NotFound)?;
            let body = axum::body::boxed(axum::body::Full::from(asset.data));
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            let response = Response::builder()
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
