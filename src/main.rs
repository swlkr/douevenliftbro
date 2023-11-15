use enum_router::Routes;
use maud::{html, Markup};
use serde::{Deserialize, Serialize};

fn main() {
    #[cfg(feature = "backend")]
    match backend::main() {
        Ok(_) => {}
        Err(err) => panic!("{}", err),
    }
}

#[derive(Clone, Copy, Routes, Default)]
pub enum Route {
    #[route("/")]
    Index,
    #[route("/signup")]
    Signup,
    #[route("/create-first-set")]
    CreateFirstSet,
    #[route("/profile")]
    Profile,
    #[route("/login")]
    Login,
    #[route("/logout")]
    Logout,
    #[route("/search-sets")]
    SearchExercises,
    #[route("/static/*file")]
    File,
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
    #[route("/sets")]
    SetList,
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

pub fn set_list_component(sets: &Vec<Set>) -> Markup {
    html! {
        div class="text-2xl text-center h-screen" {
            div class="flex flex-col gap-4 divide divide-y dark:divide-gray-700" {
                @for set in sets {
                    div class="flex gap-4" {
                        p { (set.name) }
                        p { (set.reps) " reps" }
                    }
                }
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SetParams {
    reps: u16,
    exercise_id: String,
}

pub fn index_component(is_logged_in: bool, ex: Exercise) -> Markup {
    html! {
        form {
            input type="hidden" name="exercise_id" value=(ex.id);
            div class="flex flex-col gap-8 px-4 lg:px-0" {
                div class="text-center text-2xl" {
                    (ex.name)
                }
                (display("reps", 0))
                div class="grid grid-rows-4 grid-cols-3 gap-4 mx-auto" {
                    @for digit in 1..=9 {
                        (PushParams { digit })
                    }
                    (circle_button(Route::Pop, Swap::OuterHTML, Target::Display, "del"))
                    (PushParams { digit: 0 })
                    @if is_logged_in {
                        (circle_button(Route::CreateSet, Swap::InnerHTML, Target::Body, "ok"))
                    } @else {
                        (circle_button(Route::CreateFirstSet, Swap::InnerHTML, Target::Body, "ok"))
                    }
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
    use crate::{
        button, db, index_component, set_list_component, Error, Exercise, Result, Route, Set,
        SetParams, Swap, Target,
    };
    use axum::extract::rejection::TypedHeaderRejection;
    use axum::extract::{FromRef, State};
    use axum::headers::Header;
    use axum::http::header::{HeaderName, HeaderValue, SET_COOKIE};
    use axum::{
        async_trait,
        extract::FromRequestParts,
        headers::Cookie,
        http::{
            header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE},
            Uri,
        },
        middleware::{self, Next},
        response::{AppendHeaders, IntoResponse, Response},
        routing::{get, post, IntoMakeService},
        Json, Router, Server, TypedHeader,
    };
    use maud::{html, Markup, DOCTYPE};
    use rizz::{desc, eq, r#in, Connection, Database, Integer, JournalMode, Table, Text};
    use serde::{Deserialize, Serialize};

    macro_rules! id {
        () => {{
            ulid::Ulid::new().to_string()
        }};
    }

    #[tokio::main]
    pub async fn main() -> Result<()> {
        let connection = Connection::new("db.sqlite3")
            .create_if_missing(true)
            .journal_mode(JournalMode::Wal)
            .foreign_keys(true)
            .open()
            .await?;
        let db = connection.database();
        let users = Users::new();
        let sessions = Sessions::new();
        let sets = Sets::new();
        let exercises = Exercises::new();

        let vb = Vibe {
            db,
            users,
            sessions,
            sets,
            exercises,
            user: None,
            is_htmx_request: false,
        };

        let _ = vb.migrate().await?;

        let addr = "127.0.0.1:9006".parse().unwrap();
        println!("Listening on localhost:9006");
        Server::bind(&addr).serve(routes(vb)).await.unwrap();
        Ok(())
    }

    fn routes(vb: Vibe) -> IntoMakeService<Router> {
        Router::new()
            .route(Route::File.into(), get(static_file_response))
            .route(Route::Index.into(), get(index_response))
            .route(Route::Logout.into(), post(logout_response))
            .route(Route::SetList.into(), get(set_list_response))
            .route(
                Route::CreateFirstSet.into(),
                post(create_first_set_response),
            )
            .route(
                Route::Signup.into(),
                get(signup_form_response).post(signup_response),
            )
            .route(
                Route::Login.into(),
                get(login_form_response).post(login_response),
            )
            .route(Route::CreateSet.into(), post(create_set_response))
            .route(Route::Profile.into(), get(profile_response))
            .layer(middleware::from_fn(csp_middleware))
            .with_state(vb)
            .into_make_service()
    }

    async fn profile_response(vibe: Vibe, user: User) -> Result<impl IntoResponse> {
        vibe.render(profile_component(user))
    }

    async fn create_set_response(
        vb: Vibe,
        user: User,
        Json(params): Json<SetParams>,
    ) -> Result<impl IntoResponse> {
        let Vibe { db, sets, .. } = &vb;
        let _set = db
            .insert(*sets)
            .values(db::Set {
                id: id!(),
                user_id: user.id.clone(),
                exercise_id: params.exercise_id,
                reps: params.reps,
                weight: 0,
                created_at: now(),
            })?
            .returning::<db::Set>()
            .await?;

        let sets = &vb.sets_for_user(user).await?;

        Ok((
            AppendHeaders([("Hx-Push-Url", Route::SetList.to_string())]),
            vb.render(set_list_component(sets)),
        ))
    }

    fn render_signup_form() -> Markup {
        html! {
            div class="flex flex-col pt-4 px-4 lg:px-0 max-w-sm mx-auto" {
                (rect_button(Route::Signup, Swap::InnerHTML, Target::Body, "track your workout right now"))
                (link(Route::Login, Swap::InnerHTML, Target::Body, "click here if you already have an account"))
            }
        }
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

    fn nav(user: Option<&User>) -> Markup {
        html! {
            div class="text-2xl py-4 mb-4 bg-indigo-500 text-white text-center flex justify-center gap-4 max-w-md" {
                (nav_link(Route::Index, Swap::InnerHTML, Target::Body, "/"))
                @if let None = user {
                    (nav_link(Route::Signup, Swap::InnerHTML, Target::Body, "signup"))
                } @else {
                    (nav_button(Route::Logout, Swap::InnerHTML, Target::Body, "logout"))
                }
            }
        }
    }

    fn body(user: Option<&User>, children: Markup) -> Markup {
        html! {
            body id="body" class="h-screen dark:bg-gray-950 dark:text-white max-w-lg mx-auto" hx-ext="json-enc" {
                (nav(user))
                (children)
            }
        }
    }

    async fn logout_response(vibe: Vibe) -> Result<impl IntoResponse> {
        let Vibe { db, exercises, .. } = vibe;
        let pushups = db
            .select()
            .from(exercises)
            .r#where(eq(exercises.name, "standard push-ups"))
            .first::<Exercise>()
            .await?;
        Ok((
            AppendHeaders([(
                SET_COOKIE,
                format!("id=; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",),
            )]),
            index_component(false, pushups),
        ))
    }

    async fn set_list_response(vibe: Vibe, user: User) -> Result<impl IntoResponse> {
        let sets = vibe.sets_for_user(user).await?;
        vibe.render(set_list_component(&sets))
    }

    async fn index_response(State(_): State<Vibe>, vb: Vibe) -> Result<impl IntoResponse> {
        let Vibe {
            ref db, exercises, ..
        } = vb;
        let pushups = db
            .select()
            .from(exercises)
            .r#where(eq(exercises.name, "standard push-ups"))
            .first::<Exercise>()
            .await?;

        vb.render(index_component(vb.user.is_some(), pushups))
    }

    async fn create_first_set_response(vibe: Vibe, MaybeUser(user): MaybeUser) -> Result<Markup> {
        let Vibe {
            ref db, exercises, ..
        } = vibe;
        let pushups = db
            .select()
            .from(exercises)
            .r#where(eq(exercises.name, "standard push-ups"))
            .first::<Exercise>()
            .await?;

        Ok(index_component(user.is_some(), pushups))
    }

    #[derive(Serialize, Deserialize)]
    struct LoginParams {
        secret: String,
    }

    fn login_form_component() -> Markup {
        html! {
            div class="flex flex-col pt-4 px-4 lg:px-0 max-w-sm mx-auto" {
                form {
                    input type="text" name="secret";
                    (rect_button(Route::Login, Swap::InnerHTML, Target::Body, "get back to working out"))
                }
                (link(Route::Signup, Swap::InnerHTML, Target::Body, "click here to signup"))
            }
        }
    }

    async fn login_form_response(vb: Vibe) -> Result<impl IntoResponse> {
        vb.render(login_form_component())
    }

    async fn login_response(
        vb: Vibe,
        Json(params): Json<LoginParams>,
    ) -> Result<impl IntoResponse> {
        let Vibe {
            ref db,
            users,
            sessions,
            exercises,
            ..
        } = vb;
        let maybe_user = db
            .select()
            .from(users)
            .r#where(eq(users.secret, params.secret))
            .first::<User>()
            .await;

        match maybe_user {
            Ok(user) => {
                let session = db
                    .insert(sessions)
                    .values(Session {
                        id: id!(),
                        user_id: user.id,
                        created_at: now(),
                    })?
                    .returning::<Session>()
                    .await?;

                let pushups = db
                    .select()
                    .from(exercises)
                    .r#where(eq(exercises.name, "standard push-ups"))
                    .first::<Exercise>()
                    .await?;

                Ok((
                    AppendHeaders([(
                        SET_COOKIE,
                        format!(
                            "id={}; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",
                            session.id
                        ),
                    )]),
                    index_component(true, pushups),
                )
                    .into_response())
            }
            Err(err) => match err {
                rizz::Error::RowNotFound => Ok(vb.render(login_form_component()).into_response()),
                _ => Err(err.into()),
            },
        }
    }

    fn parse_reps_cookie(cookie: Cookie) -> Option<u16> {
        cookie.get("reps")?.parse::<u16>().ok()
    }

    async fn signup_form_response(vibe: Vibe) -> Result<impl IntoResponse> {
        vibe.render(render_signup_form())
    }

    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now();
        now.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    async fn signup_response(
        State(vb): State<Vibe>,
        TypedHeader(cookie): TypedHeader<Cookie>,
    ) -> Result<impl IntoResponse> {
        let Vibe {
            ref db,
            users,
            sessions,
            sets,
            exercises,
            ..
        } = vb;
        let user: User = db
            .insert(users)
            .values(User {
                id: id!(),
                secret: id!(),
                created_at: now(),
            })?
            .returning()
            .await?;

        let session: Session = db
            .insert(sessions)
            .values(Session {
                id: id!(),
                user_id: user.id.clone(),
                created_at: now(),
            })?
            .returning()
            .await?;

        let reps = parse_reps_cookie(cookie);
        let pushups = db
            .select()
            .from(exercises)
            .r#where(eq(exercises.name, "standard push-ups"))
            .first::<Exercise>()
            .await?;

        let _set: db::Set = db
            .insert(sets)
            .values(db::Set {
                id: id!(),
                user_id: user.id.clone(),
                exercise_id: pushups.id,
                reps: reps.unwrap_or_default(),
                weight: 0,
                created_at: now(),
            })?
            .returning()
            .await?;

        Ok((
            AppendHeaders([(
                SET_COOKIE,
                format!(
                    "id={}; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",
                    session.id
                ),
            )]),
            vb.render(profile_component(user)),
        ))
    }

    fn profile_component(user: User) -> Markup {
        html! {
            div class="flex flex-col gap-4 pt-4 grid place-content-center h-full" {
                p class="" { "This is your secret key, don't lose it it's the only way to view your workouts!" }
                p class="text-xl font-bold" { (user.secret) }
                p class="text-center text-4xl" { "🎉" }
                (rect_button(Route::SearchExercises, Swap::InnerHTML, Target::Body, "add another set"))
            }
        }
    }

    async fn static_file_response(uri: Uri) -> impl IntoResponse {
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

    impl From<rizz::Error> for Error {
        fn from(value: rizz::Error) -> Self {
            match value {
                rizz::Error::RowNotFound => Error::NotFound,
                rizz::Error::Database(err) => Error::Database(err),
                _ => Error::InternalServer,
            }
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

    type MightError = std::result::Result<(), Error>;

    #[derive(Clone, Debug)]
    struct Vibe {
        db: Database,
        users: Users,
        sessions: Sessions,
        sets: Sets,
        exercises: Exercises,
        user: Option<User>,
        is_htmx_request: bool,
    }

    #[derive(Eq, PartialEq, Clone, Hash)]
    struct HxRequest(String);

    static HX_REQUEST: HeaderName = HeaderName::from_static("hx-request");

    impl Header for HxRequest {
        fn name() -> &'static HeaderName {
            &HX_REQUEST
        }

        fn decode<'i, I>(values: &mut I) -> std::result::Result<Self, axum::headers::Error>
        where
            Self: Sized,
            I: Iterator<Item = &'i axum::http::HeaderValue>,
        {
            values
                .next()
                .and_then(|v| v.to_str().ok())
                .map(|it| HxRequest(it.to_string()))
                .ok_or(axum::headers::Error::invalid())
        }

        fn encode<E: Extend<axum::http::HeaderValue>>(&self, values: &mut E) {
            let bytes = self.0.as_str().as_bytes();
            let val = HeaderValue::from_bytes(bytes).expect("Hx-Request is a valid HeaderValue");
            values.extend(::std::iter::once(val))
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for Vibe
    where
        Vibe: FromRef<S>,
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let State(mut vibe) = State::<Vibe>::from_request_parts(parts, state)
                .await
                .map_err(|_| Error::NotFound)?;
            let user = MaybeUser::from_request_parts(parts, state).await?;
            vibe.user = user.0;

            let maybe_hx_request = TypedHeader::<HxRequest>::from_request_parts(parts, state).await;
            vibe.is_htmx_request = maybe_hx_request.is_ok();

            Ok(vibe)
        }
    }

    impl Vibe {
        async fn migrate(&self) -> MightError {
            let _ = self
                .db
                .create_table(self.users)
                .create_table(self.sessions)
                .create_table(self.exercises)
                .create_unique_index(self.exercises, vec![self.exercises.name])
                .create_table(self.sets)
                .migrate()
                .await?;

            let maybe_ex = self
                .db
                .select()
                .from(self.exercises)
                .limit(1)
                .first::<Exercise>()
                .await;

            if let Err(rizz::Error::RowNotFound) = maybe_ex {
                let rows = std::fs::read_to_string("./exercises.csv")
                    .expect("exercises.csv doesn't exist");
                for line in rows.split("\n") {
                    let name = line.trim();
                    let _rows = self
                        .db
                        .insert(self.exercises)
                        .values(Exercise {
                            id: id!(),
                            name: name.into(),
                            created_at: now(),
                        })?
                        .rows_affected()
                        .await?;
                }
            }

            Ok(())
        }

        fn render(&self, children: Markup) -> Result<impl IntoResponse> {
            Ok(html! {
                (DOCTYPE)
                html {
                    (head())
                    (body(self.user.as_ref(), children))
                }
            })
        }

        async fn sets_for_user(&self, user: User) -> Result<Vec<Set>> {
            let Self {
                ref db,
                sets,
                exercises,
                ..
            } = *self;
            let sets = db
                .select()
                .from(sets)
                .r#where(eq(sets.user_id, user.id.clone()))
                .limit(30)
                .order(vec![desc(sets.created_at)])
                .all::<db::Set>()
                .await?;

            let ids = sets.iter().map(|s| &s.exercise_id).collect::<Vec<_>>();
            let exs = db
                .select()
                .from(exercises)
                .r#where(r#in(exercises.id, ids))
                .all::<Exercise>()
                .await?;

            let sets: Vec<Set> = sets
                .into_iter()
                .map(|db::Set { reps, .. }| {
                    let name = exs
                        .iter()
                        .map(|ex| ex.name.clone())
                        .last()
                        .unwrap_or_default();
                    Set { name, reps }
                })
                .collect::<Vec<_>>();

            Ok(sets)
        }
    }

    struct MaybeUser(Option<User>);

    #[async_trait]
    impl<S> FromRequestParts<S> for MaybeUser
    where
        Vibe: FromRef<S>,
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let user = User::from_request_parts(parts, state).await;

            match user {
                Ok(user) => Ok(MaybeUser(Some(user))),
                Err(err) => match err {
                    Error::NotFound | Error::RowNotFound => Ok(MaybeUser(None)),
                    _ => Err(err),
                },
            }
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for User
    where
        Vibe: FromRef<S>,
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let TypedHeader(cookie) = TypedHeader::<Cookie>::from_request_parts(parts, state)
                .await
                .map_err(|_| Error::NotFound)?;

            let id = cookie.get("id").ok_or(Error::NotFound)?;

            let State(Vibe {
                ref db,
                sessions,
                users,
                ..
            }) = State::<Vibe>::from_request_parts(parts, state)
                .await
                .map_err(|_| Error::NotFound)?;

            // TODO: this should be a transaction or a join
            let session = db
                .select()
                .from(sessions)
                .r#where(eq(sessions.id, id))
                .first::<Session>()
                .await?;
            let user = db
                .select()
                .from(users)
                .r#where(eq(users.id, session.user_id))
                .first::<User>()
                .await?;

            Ok(user)
        }
    }

    pub fn rect_button(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            (button(route, swap, target, "flex rounded-md bg-indigo-500 hover:bg-indigo-600 active:bg-indigo-700 text-white p-4 items-center justify-center uppercase", children))
        }
    }

    pub fn link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            a class="text-indigo-500 hover:text-indigo-600 active:text-indigo-700 hover:underline" hx-get=(route) hx-target=(target) hx-swap=(swap) hx-push-url=(route) { (children) }
        }
    }

    pub fn nav_link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            a class="hover:text-indigo-900 active:text-indigo-700 hover:underline"
            hx-get=(route)
            hx-target=(target)
            hx-swap=(swap)
            hx-push-url=(route) {
                (children)
            }
        }
    }

    pub fn nav_button(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            a class="hover:text-indigo-900 active:text-indigo-700 hover:underline"
            hx-post=(route)
            hx-target=(target)
            hx-swap=(swap)
            hx-push-url=(route) {
                (children)
            }
        }
    }

    #[derive(Table, Clone, Copy, Debug)]
    #[rizz(table = "users")]
    pub struct Users {
        #[rizz(primary_key)]
        pub id: Text,
        #[rizz(not_null)]
        pub secret: Text,
        #[rizz(not_null)]
        pub created_at: Integer,
    }

    #[derive(Table, Clone, Copy, Debug)]
    #[rizz(table = "sessions")]
    pub struct Sessions {
        #[rizz(primary_key)]
        pub id: Text,
        #[rizz(references = "users(id)", not_null)]
        pub user_id: Text,
        #[rizz(not_null)]
        pub created_at: Integer,
    }

    #[derive(Table, Clone, Copy, Debug)]
    #[rizz(table = "exercises")]
    pub struct Exercises {
        #[rizz(primary_key)]
        pub id: Text,
        #[rizz(not_null)]
        pub name: Text,
        #[rizz(not_null)]
        pub created_at: Integer,
    }

    #[derive(Table, Clone, Copy, Debug)]
    #[rizz(table = "sets")]
    pub struct Sets {
        #[rizz(primary_key)]
        pub id: Text,
        #[rizz(references = "users(id)", not_null)]
        pub user_id: Text,
        #[rizz(references = "exercises(id)", not_null)]
        pub exercise_id: Text,
        #[rizz(not_null)]
        pub reps: Integer,
        #[rizz(not_null)]
        pub weight: Integer,
        #[rizz(not_null)]
        pub created_at: Integer,
    }

    #[derive(Clone, Default, Serialize, Deserialize, Debug)]
    pub struct User {
        pub id: String,
        pub secret: String,
        pub created_at: u64,
    }

    #[derive(Default, Serialize, Deserialize)]
    pub struct Session {
        pub id: String,
        pub user_id: String,
        pub created_at: u64,
    }

    impl From<TypedHeaderRejection> for Error {
        fn from(value: TypedHeaderRejection) -> Self {
            Error::InvalidHeader(value.to_string())
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Set {
    reps: u16,
    name: String,
}

mod db {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Default)]
    pub struct Set {
        pub id: String,
        pub user_id: String,
        pub exercise_id: String,
        pub reps: u16,
        pub weight: u16,
        pub created_at: u64,
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

#[allow(unused)]
#[justerror::Error]
#[derive(Clone)]
pub enum Error {
    NotFound,
    InternalServer,
    RowNotFound,
    Database(String),
    InvalidHeader(String),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize)]
pub struct Exercise {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}
