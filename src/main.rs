use enum_router::Routes;
use maud::{html, Markup};
use serde::{Deserialize, Serialize};

fn main() {
    #[cfg(feature = "backend")]
    backend::main()
}

#[derive(Clone, Copy, Routes, Default)]
pub enum Route {
    #[route("/")]
    Root,
    #[route("/static/*file")]
    FileRequested,
    #[default]
    #[route("/404")]
    NotFound,
    #[route("/frontend/inc")]
    Inc,
    #[route("/frontend/dec")]
    Dec,
    #[route("/frontend/push")]
    Push,
    #[route("/frontend/pop")]
    Pop,
    #[route("/create-set")]
    CreateSet,
}

pub fn button(
    route: Route,
    swap: Swap,
    target: Target,
    class: &str,
    children: impl std::fmt::Display,
) -> Markup {
    let target = format!("#{}", target);

    html! {
        button
            class=(class)
            hx-post=(route)
            hx-swap=(swap)
            hx-target=(target) {
            (children)
        }
    }
}

pub fn display_value(value: u16) -> Markup {
    html! {
        div id=(Target::Display) class="text-6xl" {
            input type="hidden" name="reps" value=(value);
            (value)
        }
    }
}

pub fn display(label: &str, value: u16) -> Markup {
    html! {
        div class="border rounded-xl flex justify-between items-end p-4" {
            div class="text-md" {
                (label)
            }
            (display_value(value))
        }
    }
}

pub fn circle_button(
    route: Route,
    swap: Swap,
    target: Target,
    children: impl std::fmt::Display,
) -> Markup {
    html! {
        (button(route, swap, target, "flex rounded-full p-4 border dark:border-white border-slate-600 items-center justify-center border-2 w-20 h-20", children))
    }
}

pub fn render_good_job() -> Markup {
    html! {
        div class="text-2xl text-center grid place-content-center h-screen" {
            div class="flex flex-col gap-4" {
                p { "🎉" }
                p { "good job" }
            }
        }
    }
}

#[derive(Default, Debug, Serialize, Deserialize)]
struct Set {
    id: String,
    name: String,
    reps: u16,
    weight: u16,
    started_at: u64,
    ended_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct SetParams {
    reps: u16,
}

pub fn render_set_form() -> Markup {
    let set = Set {
        name: "push ups".into(),
        ..Default::default()
    };

    html! {
        form {
            div class="flex flex-col gap-8" {
                div class="text-center text-2xl" {
                    (set.name)
                }
                (display("reps", 0))
                div class="grid grid-rows-4 grid-cols-3 gap-4 mx-auto" {
                    @for digit in 1..=9 {
                        (PushParams { digit })
                    }
                    (circle_button(Route::Pop, Swap::OuterHTML, Target::Display, "del"))
                    (PushParams { digit: 0 })
                    (circle_button(Route::CreateSet, Swap::InnerHTML, Target::Body, "ok"))
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct PushParams {
    digit: u16,
}

impl maud::Render for PushParams {
    fn render(&self) -> Markup {
        html! {
            form {
                input type="hidden" name="digit" value=(self.digit);
                (circle_button(Route::Push, Swap::OuterHTML, Target::Display, self.digit))
            }
        }
    }
}

#[cfg(feature = "frontend")]
mod frontend {
    use crate::{display_value, html, Markup, PushParams, Route};
    use serde::{Deserialize, Serialize};
    use std::sync::{Mutex, MutexGuard};
    static REPS: Mutex<u16> = Mutex::new(0);

    fn push_digit(value: u16, digit: u16) -> Option<u16> {
        value.checked_mul(10)?.checked_add(digit)
    }

    fn pop_digit(value: u16) -> Option<u16> {
        let rem = value.checked_rem(10)?;
        value.checked_sub(rem)?.checked_div(10)
    }

    fn push(request: &Request) -> Markup {
        let PushParams { digit } = serde_json::from_str::<PushParams>(&request.body)
            .expect("could not parse value from request body");
        let reps = *REPS.lock().unwrap();
        match push_digit(reps, digit) {
            Some(new_reps) => {
                *REPS.lock().unwrap() = new_reps;
                display_value(new_reps)
            }
            None => display_value(reps),
        }
    }

    fn pop(_request: &Request) -> Markup {
        let reps = *REPS.lock().unwrap();
        match pop_digit(reps) {
            Some(new_reps) => {
                *REPS.lock().unwrap() = new_reps;
                display_value(new_reps)
            }
            None => display_value(reps),
        }
    }

    fn not_found(_request: &Request) -> Markup {
        html! { "not found" }
    }

    fn route(request: &Request) -> Markup {
        let route = Route::from(request.path());
        let handler = match route {
            Route::Push => push,
            Route::Pop => pop,
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
    use crate::{render_good_job, render_set_form, Route, SetParams};
    use axum::{
        async_trait,
        extract::FromRequestParts,
        http::{
            header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE},
            Uri,
        },
        middleware::{self, Next},
        response::{IntoResponse, Response},
        routing::{get, post, IntoMakeService},
        Json, Router, Server,
    };
    use maud::{html, Markup, DOCTYPE};

    #[tokio::main]
    pub async fn main() {
        let addr = "127.0.0.1:9006".parse().unwrap();
        println!("Listening on localhost:9006");
        Server::bind(&addr).serve(routes()).await.unwrap();
    }

    fn routes() -> IntoMakeService<Router> {
        Router::new()
            .route(&Route::Root.to_string(), get(route_to_root))
            .route(&Route::CreateSet.to_string(), post(route_to_create_set))
            .route(&Route::FileRequested.to_string(), get(route_to_static_file))
            .layer(middleware::from_fn(csp_middleware))
            .into_make_service()
    }

    async fn route_to_create_set(Json(_params): Json<SetParams>) -> Markup {
        render_good_job()
    }

    async fn csp_middleware<B>(request: axum::http::Request<B>, next: Next<B>) -> Response {
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(
                "default-src 'self'; frame-ancestors 'none'; script-src 'self' 'wasm-unsafe-eval'",
            ),
        );

        response
    }

    fn read_static_files_from_fs() -> Vec<Markup> {
        StaticFiles::iter()
            .map(|file| file.to_string())
            .map(|path| (StaticFiles::get(&path), path))
            .filter_map(|(maybe_file, path)| match maybe_file {
                Some(file) => Some(format!("{}?v={}", path, file.metadata.last_modified()?)),
                None => None,
            })
            .map(|uri| {
                if uri.contains(".js") {
                    html! { script defer src=(uri) {} }
                } else if uri.contains(".css") {
                    html! { link href=(uri) rel="stylesheet"; }
                } else {
                    html! {}
                }
            })
            .collect::<Vec<_>>()
    }

    fn head() -> Markup {
        html! {
            head {
                @for static_file in read_static_files_from_fs() {
                    (static_file)
                }
                title { "do u even lift bro?" }
                meta content="text/html;charset=utf-8" http-equiv="Content-Type";
                meta name="viewport" content="width=device-width, initial-scale=1";
                meta charset="UTF-8";
            }
        }
    }

    fn body(children: Markup) -> Markup {
        html! {
            body id="body" class="dark:bg-gray-950 dark:text-white px-4 lg:px-0 max-w-lg mx-auto" hx-ext="json-enc" { (children) }
        }
    }

    async fn route_to_root(cx: Context) -> Markup {
        cx.render(render_set_form())
    }

    async fn route_to_static_file(uri: Uri) -> impl IntoResponse {
        StaticFile(uri.path().to_string())
    }

    #[derive(rust_embed::RustEmbed)]
    #[folder = "static"]
    #[prefix = "/static/"]
    pub struct StaticFiles;

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
            let asset = StaticFiles::get(path.as_str()).ok_or(Error::NotFound)?;
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

    #[derive(Clone, Debug)]
    struct Context {}

    impl Context {
        fn render(&self, children: Markup) -> Markup {
            html! {
                (DOCTYPE)
                html {
                    (head())
                    (body(children))
                }
            }
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for Context
    where
        // AppState: FromRef<S>,
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            _parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            Ok(Self {})
        }
    }
}

#[derive(Clone, Copy, Default)]
pub enum Target {
    Body,
    Display,
    Counter,
    #[default]
    This,
}

#[derive(Clone, Copy, Default)]
pub enum Swap {
    #[default]
    InnerHTML,
    OuterHTML,
    BeforeBegin,
    AfterBegin,
    BeforeEnd,
    AfterEnd,
    Delete,
    None,
}

impl std::fmt::Display for Swap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Swap::InnerHTML => "innerHTML",
            Swap::OuterHTML => "outerHTML",
            Swap::BeforeBegin => "beforebegin",
            Swap::AfterBegin => "afterbegin",
            Swap::BeforeEnd => "beforeend",
            Swap::AfterEnd => "afterend",
            Swap::Delete => "delete",
            Swap::None => "none",
        })
    }
}

#[derive(Default)]
pub struct Hx {
    pub get: Route,
    pub post: Route,
    pub swap: Swap,
    pub target: Target,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Target::Counter => "counter",
            Target::This => "this",
            Target::Display => "display",
            Target::Body => "body",
        })
    }
}
