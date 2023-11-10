use maud::{html, Markup};

fn main() {
    #[cfg(feature = "backend")]
    backend::main()
}

pub fn count(count: i64) -> Markup {
    html! {
        div data-id="target" { "count:" (count) }
    }
}

pub fn counter() -> Markup {
    html! {
        (count(0))
        button hx-post="./;inc" hx-swap="outerHTML" hx-target="[data-id='target']" { "add" }
        button hx-post="./;dec" hx-swap="outerHTML" hx-target="[data-id='target']" { "subtract" }
    }
}

#[cfg(feature = "frontend")]
mod frontend {
    use crate::{count, html, Markup};
    use matchit::Params;
    use serde::{Deserialize, Serialize};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    type Handler = fn(&Params, &Request) -> String;
    type Router = matchit::Router<Handler>;

    static COUNTER: Mutex<i64> = Mutex::new(0);
    static ROUTER: OnceLock<Result<Router>> = OnceLock::new();

    fn routes() -> Result<Router> {
        let mut router = Router::new();
        router.insert("/;inc", |_, _r| inc().into())?;
        router.insert("/;dec", |_, _r| dec().into())?;

        Ok(router)
    }

    fn dec() -> Markup {
        *(COUNTER.lock().unwrap()) -= 1;

        count(*COUNTER.lock().unwrap())
    }

    fn inc() -> Markup {
        *(COUNTER.lock().unwrap()) += 1;

        count(*COUNTER.lock().unwrap())
    }

    fn handle_request(request: &Request) -> String {
        let router = match ROUTER.get_or_init(|| routes()) {
            Ok(r) => r,
            Err(e) => return html! { p { "Failed to build router" (e) } }.into(),
        };
        let path = request.path().trim_start_matches("/wasm-service");
        let (handler, params) = match router.at(path) {
            Ok(ok) => (ok.value, ok.params),
            Err(matchit::MatchError::NotFound) => return html! { p { "Not found" } }.into(),
            Err(e) => return html! { p { "Error matching request handler: " (e) } }.into(),
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

    use crate::counter;

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

    fn head() -> Markup {
        html! {
            head {
                script src="/pub/htmx.js" {}
                script src="/pub/json-enc.js" {}
                script {
                    (maud::PreEscaped(r#"
                        if ("serviceWorker" in navigator) {
                          navigator.serviceWorker.register("/pub/sw.js")
                            .then(reg => {
                              reg.addEventListener('statechange', event => {
                                console.log("received `statechange` event", { reg, event })
                              });
                              console.log("service worker registered", reg);
                              setTimeout(() => {
                                  reg.active.postMessage({ type: 'clientattached' });
                              }, 100);
                            }).catch(err => {
                              console.error("service worker registration failed", err);
                            });
                          navigator.serviceWorker.addEventListener('controllerchange', event => {
                            console.log("received `controllerchange` event", event);
                          });
                        } else {
                          console.error("serviceWorker is missing from `navigator`. Note service workers must be served over https or on localhost");
                        }
                    "#))
                }
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
        let path = uri.path().trim_start_matches('/').to_string();
        StaticFile(path)
    }

    #[derive(rust_embed::RustEmbed)]
    #[folder = "pub"]
    #[prefix = "pub/"]
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
