#![allow(non_snake_case)]

use maud::{html, Markup, Render};
use serde::{Deserialize, Serialize};

use crate::class::CIRCLE_BUTTON;

fn main() {
    #[cfg(feature = "backend")]
    match backend::main() {
        Ok(_) => {}
        Err(err) => panic!("{}", err),
    }
}

#[cfg(feature = "backend")]
pub mod backend {
    use crate::{
        button,
        class::{CIRCLE_BUTTON, RECT_BUTTON},
        display_value, input_reps, Error, Hx, Push, Swap, Target,
    };
    use axum::{
        async_trait,
        extract::{rejection::TypedHeaderRejection, FromRequestParts, Path, Query},
        http::{
            header::{CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, SET_COOKIE},
            Uri,
        },
        middleware::{self, Next},
        response::{AppendHeaders, IntoResponse},
        routing::IntoMakeService,
        Json, Router, Server, TypedHeader,
    };
    use enum_router::Routes;

    use maud::{html, Markup, PreEscaped, Render, DOCTYPE};
    use rizz::{desc, eq, Connection, Integer, JournalMode, Table, Text};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::{fmt::Display, sync::OnceLock};

    macro_rules! ulid {
        () => {{
            ulid::Ulid::new().to_string()
        }};
    }

    #[tokio::main]
    pub async fn main() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
        let db = Connection::new("db.sqlite3")
            .create_if_missing(true)
            .journal_mode(JournalMode::Wal)
            .foreign_keys(true)
            .open()
            .await
            .expect("Could not connect to database")
            .database();
        let db = Database::new(db);
        let _ = db.migrate().await?;

        DB.set(db).unwrap();
        let static_file_tags = static_file_tags();
        STATIC_FILE_TAGS.set(static_file_tags).unwrap();

        let addr = "127.0.0.1:9006".parse().unwrap();
        println!("Listening on localhost:9006");
        Server::bind(&addr).serve(routes()).await.unwrap();
        Ok(())
    }

    fn routes() -> IntoMakeService<Router> {
        Route::router()
            .route("/static/*file", axum::routing::get(file))
            .layer(middleware::from_fn(csp_middleware))
            .into_make_service()
    }

    fn AddSet(name: String, user: Option<User>, reps: u16) -> Markup {
        let route = match user {
            Some(_) => Route::AddSetAction,
            None => Route::Signup,
        };
        let target = Target::Display.selector();
        html! {
            div class="flex flex-col gap-8 px-4 lg:px-0" {
                div class="border rounded-xl flex justify-between items-end p-4" {
                    div class="text-md" { "reps" }
                    (display_value(reps))
                }
                div class="grid grid-rows-4 grid-cols-3 gap-4 mx-auto" {
                    @for digit in 1..=9 {
                        (Push { digit })
                    }
                    button class=(CIRCLE_BUTTON) hx-post=(crate::Route::Pop) hx-swap=(Swap::OuterHTML) hx-target=(target) { "del" }
                    (Push { digit: 0 })
                    form {
                        (input_reps(0, false))
                        (hidden_input("name", &name))
                        button class=(CIRCLE_BUTTON) hx-post=(route) hx-swap=(Swap::OuterHTML) hx-target=(Target::Body) { "ok" }
                    }
                }
                div class="text-center text-2xl" {
                    (&name)
                }
            }
        }
    }

    async fn profile(vibe: Vibe, user: User) -> Result<impl IntoResponse> {
        vibe.render(Profile(user))
    }

    async fn csp_middleware<B>(
        request: axum::http::Request<B>,
        next: Next<B>,
    ) -> axum::response::Response {
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            CONTENT_SECURITY_POLICY,
            axum::http::HeaderValue::from_static(
                "default-src 'self'; frame-ancestors 'none'; script-src 'self' 'wasm-unsafe-eval'",
            ),
        );

        response
    }

    fn static_file_tags() -> Vec<Markup> {
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

    fn head(file_tags: &Vec<Markup>) -> Markup {
        html! {
            head {
                @for tag in file_tags {
                    (tag)
                }
                title { "do u even lift bro?" }
                meta content="text/html;charset=utf-8" http-equiv="Content-Type";
                meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no";
                meta charset="UTF-8";
            }
        }
    }

    fn person_square_icon() -> Markup {
        html! {
            svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-person-square" viewBox="0 0 16 16" {
              path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0z" {}
              path d="M2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H2zm12 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1v-1c0-1-1-4-6-4s-6 3-6 4v1a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h12z" {}
            }
        }
    }

    fn house_icon() -> Markup {
        html! {
            svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-house" viewBox="0 0 16 16" {
              path d="M8.707 1.5a1 1 0 0 0-1.414 0L.646 8.146a.5.5 0 0 0 .708.708L2 8.207V13.5A1.5 1.5 0 0 0 3.5 15h9a1.5 1.5 0 0 0 1.5-1.5V8.207l.646.647a.5.5 0 0 0 .708-.708L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.707 1.5ZM13 7.207V13.5a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5V7.207l5-5 5 5Z";
            }
        }
    }

    fn plus_square_icon() -> Markup {
        html! {
            svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="currentColor" class="bi bi-plus-square" viewBox="0 0 16 16" {
              path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h12zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2H2z" {}
              path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4z" {}
            }
        }
    }

    fn nav(children: impl Render) -> Markup {
        html! {
            nav class="py-4 bg-orange-500 text-white text-center flex justify-around gap-4 fixed bottom-0 left-0 right-0 lg:top-0 lg:bottom-auto w-full lg:max-w-md lg:mx-auto" {
                (children)
            }
        }
    }

    fn user_nav() -> Markup {
        nav(html! {
            (nav_link(Route::ForYou, Swap::InnerHTML, Target::Body, house_icon()))
            (nav_link(Route::AddSet("push ups".into()), Swap::InnerHTML, Target::Body, plus_square_icon()))
            (nav_link(Route::Profile, Swap::InnerHTML, Target::Body, person_square_icon()))
        })
    }

    fn anon_nav() -> Markup {
        nav(html! {
            (nav_link(Route::Index, Swap::InnerHTML, Target::Body, house_icon()))
            (nav_link(Route::AddSet("push ups".into()), Swap::InnerHTML, Target::Body, plus_square_icon()))
            form {
                (hidden_input("reps", 0))
                (nav_link(Route::Signup, Swap::InnerHTML, Target::Body, person_square_icon()))
            }
        })
    }

    fn body(user: Option<&User>, children: impl Render) -> Markup {
        html! {
            body id="body" class="h-screen dark:bg-gray-900 dark:text-white" hx-ext="json-enc" {
                @match user {
                    Some(_) => (user_nav()),
                    None => (anon_nav()),
                }
                main class="max-w-lg mx-auto lg:mt-16" {
                    (children)
                }
            }
        }
    }

    fn session_cookie(id: Option<String>) -> String {
        format!(
            "id={}; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",
            id.unwrap_or_default()
        )
    }

    async fn logout(vb: Vibe) -> Result<impl IntoResponse> {
        vb.response()
            .cookie(session_cookie(None))
            .hx_location(Route::Index)
            .render(Index())
    }

    fn Index() -> Markup {
        html! {
            div class="flex flex-col gap-4 text-left p-4 lg:p-0 mx-auto max-w-md items-center justify-center h-screen" {
                h1 class="text-8xl" { "sup bro." }
                h1 class="text-8xl" { "u lift?" }
                (SignupButton(0))
            }
        }
    }

    async fn index(vb: Vibe) -> Result<impl IntoResponse> {
        vb.render(Index())
    }

    fn List<T>(rows: &Vec<T>) -> Markup
    where
        T: Render,
    {
        html! {
            ul class="divide-y dark:divide-gray-800" {
                @for row in rows {
                    (row)
                }
            }
        }
    }

    fn SetRow(set: &Set) -> Markup {
        html! {
            li class="p-4" {
                (set.name)
            }

        }
    }

    fn ForYou(_user: &User, sets: &Vec<Set>) -> Markup {
        let rows = sets.iter().map(|s| SetRow(&s)).collect::<Vec<_>>();
        html! {
            @if rows.is_empty() {
                div class="flex flex-col gap-8" {
                    h1 class="text-4xl" { "u haven't lifted" }
                    button class=(RECT_BUTTON) hx-get=(Route::AddSet("push ups".into())) {
                        "starting lifting"
                    }
                }

            } @else {
                (List(&rows))
            }
        }
    }

    async fn for_you(vb: Vibe, db: Database, user: User) -> Html {
        let sets = db.sets_for_user(&user).await?;
        vb.render(ForYou(&user, &sets))
    }

    fn text_input(name: &str, value: impl Display, placeholder: impl Display) -> Markup {
        html! {
            input class="block w-full rounded-md border-0 px-2 py-4 text-gray-900 outline-0 focus:outline-0 focus:ring-0 focus-visible:outline-0 focus:outline-none placeholder:text-gray-400" name=(name) type="text" value=(value) placeholder=(placeholder);
        }
    }

    fn hidden_input(name: &str, value: impl Display) -> Markup {
        html! {
            input type="hidden" name=(name) value=(value);
        }
    }

    fn Login(reps: u16, secret: impl Display, _error: impl Display) -> Markup {
        html! {
            div class="flex flex-col gap-8 text-center pt-4 px-4 lg:px-0 max-w-sm mx-auto" {
                h1 class="text-2xl lg:text-4xl dark:text-white" { "login to workout, bro" }
                form class="flex flex-col gap-2 text-center" {
                    (text_input("secret", &secret, "Enter your secret key"))
                    (rect_button(Hx::Post(&Route::LoginAction), Swap::InnerHTML, Target::Body, "get back to working out"))
                }
                form {
                    (hidden_input("reps", reps))
                    (link(Route::Signup, Swap::InnerHTML, Target::Body, "click here to signup"))
                }
            }
        }
    }

    async fn login(vb: Vibe) -> Result<impl IntoResponse> {
        vb.render(Login(0, "", ""))
    }

    #[derive(Default, Serialize, Deserialize)]
    struct Login {
        secret: String,
    }

    fn hx_location(value: impl Display) -> (axum::http::HeaderName, axum::http::HeaderValue) {
        (
            axum::http::HeaderName::from_static("hx-location"),
            axum::http::HeaderValue::from_str(&value.to_string())
                .expect("could not assign hx_location to HeaderValue"),
        )
    }

    async fn login_action(
        vb: Vibe,
        db: Database,
        Json(json): Json<Login>,
    ) -> Result<impl IntoResponse> {
        let maybe_user = db.user_by_secret(&json.secret).await;
        let Ok(user) = maybe_user else {
            return vb
                .response()
                .render(Login(0, json.secret, "Nope try again"));
        };
        let session: Session = db
            .insert(Session {
                id: ulid!(),
                user_id: user.id.clone(),
                created_at: now(),
            })
            .await?;
        let sets = vec![];

        vb.response()
            .cookie(session_cookie(Some(session.id)))
            .hx_location(Route::ForYou)
            .render(ForYou(&user, &sets))
    }

    #[derive(Serialize, Deserialize)]
    struct SignupQuery {
        reps: Option<u16>,
    }

    async fn signup(vb: Vibe, Query(query): Query<SignupQuery>) -> Result<impl IntoResponse> {
        vb.render(Signup(query.reps.unwrap_or_default()))
    }

    fn SignupButton(reps: u16) -> Markup {
        html! {
            form class="flex mx-auto" {
                (hidden_input("reps", reps))
                button class=(RECT_BUTTON) hx-post=(Route::SignupAction) hx-target=(Target::Body.selector()) {
                    "start lifting bruh"
                }
            }
        }
    }

    fn Signup(reps: u16) -> Markup {
        html! {
            div class="flex flex-col justify-center gap-6 pt-4 px-4 lg:px-0 max-w-sm mx-auto text-center" {
                h1 class="text-2xl lg:text-4xl" { "signup to workout, bro" }
                (SignupButton(reps))
                (link(Route::Login, Swap::InnerHTML, Target::Body, "click here if you already have an account"))
            }
        }
    }

    async fn signup_action(vb: Vibe, db: Database) -> Result<impl IntoResponse> {
        // create user
        let user: User = db
            .insert(User {
                id: ulid!(),
                secret: ulid!(),
                created_at: now(),
            })
            .await?;
        // create session
        let session: Session = db
            .insert(Session {
                id: ulid!(),
                user_id: user.id.clone(),
                created_at: now(),
            })
            .await?;
        let name: String = "push ups".into();
        let route = Route::AddSet(name.clone());

        vb.response()
            .cookie(session_cookie(Some(session.id)))
            .hx_location(route)
            .render(AddSet(name, Some(user), 0))
    }

    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now();
        now.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn Profile(user: User) -> Markup {
        html! {
            div class="flex flex-col gap-4 pt-4 max-w-lg mx-auto justify-center items-center w-full h-full px-12 lg:px-0" {
                p class="" { "This is your secret key, don't lose it it's the only way to view your workouts!" }
                p class="text-xl font-bold" { (user.secret) }
                p class="text-center text-4xl" { "🎉" }
                (rect_button(Hx::Post(&Route::Logout), Swap::InnerHTML, Target::Body, "logout"))
            }
        }
    }

    async fn file(uri: Uri) -> impl IntoResponse {
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
        fn maybe_response(self) -> Result<axum::response::Response> {
            let path: String = self.0.into();
            let mut builder = axum::response::Response::builder();
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
        fn into_response(self) -> axum::response::Response {
            self.maybe_response()
                .unwrap_or(Error::NotFound.into_response())
        }
    }

    impl From<axum::http::Error> for Error {
        fn from(value: axum::http::Error) -> Self {
            Self::Http(value.to_string())
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

    impl From<axum::Error> for Error {
        fn from(value: axum::Error) -> Self {
            Self::Axum(value.to_string())
        }
    }

    impl From<std::io::Error> for Error {
        fn from(value: std::io::Error) -> Self {
            Self::Fs(value.to_string())
        }
    }

    impl IntoResponse for Error {
        fn into_response(self) -> axum::response::Response {
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
    type Html = Result<Markup>;

    #[derive(Clone, Default, Debug)]
    struct Vibe {
        user: Option<User>,
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for Vibe
    where
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let user = User::from_request_parts(parts, state).await;

            let user =
                match user {
                    Ok(user) => Some(user),
                    Err(err) => match err {
                        Error::NotFound | Error::RowNotFound => None,
                        _ => return Err(err),
                    },
                };

            Ok(Vibe { user })
        }
    }

    #[allow(unused)]
    impl Database {
        async fn migrate(&self) -> MightError {
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;

            let _ = db
                .create_table(users)
                .create_table(sessions)
                .create_table(sets)
                .migrate()
                .await?;

            Ok(())
        }

        // db.jsonl
        // {  }

        async fn insert<T: Serialize + DeserializeOwned + Sync + Send + 'static>(
            &self,
            record: impl Into<Record>,
        ) -> Result<T> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;
            match record.into() {
                Record::Set(new_set) => {
                    let row = db.insert(sets).values(new_set)?.returning::<T>().await?;
                    Ok(row)
                }
                Record::User(new_user) => {
                    let row = db.insert(users).values(new_user)?.returning::<T>().await?;
                    Ok(row)
                }
                Record::Session(new_session) => {
                    let row = db
                        .insert(sessions)
                        .values(new_session)?
                        .returning::<T>()
                        .await?;
                    Ok(row)
                }
            }
        }

        fn new(db: rizz::Database) -> Self {
            let users = Users::new();
            let sessions = Sessions::new();
            let sets = Sets::new();

            Database {
                db,
                users,
                sessions,
                sets,
            }
        }

        async fn user_by_secret(&self, secret: &str) -> Result<User> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;
            let row = db
                .select()
                .from(users)
                .r#where(eq(users.secret, secret))
                .first::<User>()
                .await?;
            Ok(row)
        }

        async fn user_by_session_id(&self, session_id: &str) -> Result<User> {
            // TODO: this should be a transaction or a join
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;

            let session = db
                .select()
                .from(sessions)
                .r#where(eq(sessions.id, session_id))
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

        async fn unique_set_names(&self, user: User) -> Result<Vec<String>> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;

            let rows = db
                .select()
                .from(sets)
                .r#where(eq(sets.user_id, user.id))
                .group_by(vec![sets.user_id, sets.name])
                .all::<Set>()
                .await?;

            let names = rows.into_iter().map(|row| row.name).collect();

            Ok(names)
        }

        async fn sets_for_user(&self, user: &User) -> Result<Vec<Set>> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
            } = *self;

            let rows = db
                .select()
                .from(sets)
                .r#where(eq(sets.user_id, &user.id))
                .order(vec![desc(sets.created_at)])
                .all::<Set>()
                .await?;

            Ok(rows)
        }
    }

    impl Vibe {
        fn render(&self, children: impl Render) -> Html {
            Ok(html! {
                (DOCTYPE)
                html {
                    (head(STATIC_FILE_TAGS.get().unwrap()))
                    (body(self.user.as_ref(), children))
                }
            })
        }

        fn redirect_to(&self, component: impl Render, route: Route) -> Result<impl IntoResponse> {
            let headers = AppendHeaders([(hx_location(route))]);
            let body = self.render(component);

            Ok((headers, body))
        }

        fn response(&self) -> VibeResponse {
            VibeResponse::new(self.clone())
        }
    }

    #[derive(Default)]
    struct VibeResponse {
        vibe: Vibe,
        headers: Option<Vec<(axum::http::HeaderName, axum::http::HeaderValue)>>,
    }

    impl VibeResponse {
        fn new(vibe: Vibe) -> Self {
            Self {
                vibe,
                ..Default::default()
            }
        }

        fn cookie(mut self, cookie: String) -> Self {
            let header_value = axum::http::HeaderValue::from_str(&cookie)
                .expect("can't set header value from str in cookie()");
            let header = (SET_COOKIE, header_value);
            match self.headers {
                Some(ref mut headers) => headers.push(header),
                None => self.headers = Some(vec![header]),
            }
            self
        }

        fn hx_location(mut self, route: Route) -> Self {
            match self.headers {
                Some(ref mut headers) => headers.push(hx_location(route)),
                None => self.headers = Some(vec![hx_location(route)]),
            }
            self
        }

        fn render(self, component: impl Render) -> Result<impl IntoResponse> {
            let mut builder = axum::response::Response::builder().status(200);
            if let Some(headers) = self.headers {
                for header in headers {
                    builder = builder.header(header.0, header.1);
                }
            }
            let response = builder.body(self.vibe.render(component).into_response())?;
            Ok(response)
        }
    }

    static DB: OnceLock<Database> = OnceLock::new();
    static STATIC_FILE_TAGS: OnceLock<Vec<Markup>> = OnceLock::new();

    fn db<'a>() -> &'a Database {
        DB.get().unwrap()
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for User
    where
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let TypedHeader(cookie) =
                TypedHeader::<axum::headers::Cookie>::from_request_parts(parts, state)
                    .await
                    .map_err(|_| Error::NotFound)?;
            let session_id = cookie.get("id").ok_or(Error::NotFound)?;
            let db = db();
            let user: User = db.user_by_session_id(session_id).await?;

            Ok(user)
        }
    }

    #[async_trait]
    impl<S> FromRequestParts<S> for Database
    where
        S: Send + Sync,
    {
        type Rejection = Error;

        async fn from_request_parts(
            _parts: &mut axum::http::request::Parts,
            _state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let db = db();

            Ok(db.clone())
        }
    }

    pub fn rect_button(
        route: Hx,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            (button(route, swap, target, "flex rounded-md bg-orange-500 active:bg-orange-700 text-white p-4 items-center justify-center uppercase w-full", children))
        }
    }

    struct Link {
        route: Route,
        swap: Swap,
        target: Target,
        children: String,
    }

    impl Render for Link {
        fn render(&self) -> Markup {
            html! {
                a class="text-orange-500 hover:text-orange-600 active:text-orange-700 hover:underline" hx-get=(self.route) hx-target=(self.target) hx-swap=(self.swap) hx-push-url=(self.route) {
                    (PreEscaped(self.children.clone()))
                }
            }
        }
    }

    pub fn link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            a class="cursor-pointer text-orange-500 hover:text-orange-600 active:text-orange-700 hover:underline" hx-get=(route) hx-target=(target) hx-swap=(swap) hx-push-url=(route) { (children) }
        }
    }

    pub fn button_link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            button class="text-orange-500 hover:text-orange-600 active:text-orange-700 hover:underline" hx-post=(route) hx-target=(target) hx-swap=(swap) hx-push-url=(route) { (children) }
        }
    }

    pub fn nav_link(route: Route, swap: Swap, target: Target, children: impl Render) -> Markup {
        html! {
            a class="active:text-gray-900 hover:underline cursor-pointer"
              hx-get=(route)
              hx-target=(target)
              hx-swap=(swap) {
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
    #[rizz(table = "sets")]
    pub struct Sets {
        #[rizz(primary_key)]
        pub id: Text,
        #[rizz(references = "users(id)", not_null)]
        pub user_id: Text,
        #[rizz(not_null)]
        pub name: Text,
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

    #[derive(Debug, Default, Serialize, Deserialize)]
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

    type Result<T> = std::result::Result<T, Error>;

    pub enum Record {
        Set(Set),
        User(User),
        Session(Session),
    }

    impl From<Set> for Record {
        fn from(set: Set) -> Self {
            Record::Set(set)
        }
    }

    impl From<Session> for Record {
        fn from(session: Session) -> Self {
            Record::Session(session)
        }
    }

    impl From<User> for Record {
        fn from(user: User) -> Self {
            Record::User(user)
        }
    }

    #[derive(Clone, Debug)]
    struct Database {
        db: rizz::Database,
        users: Users,
        sessions: Sessions,
        sets: Sets,
    }

    async fn add_set(vb: Vibe, _user: User, Path(name): Path<String>) -> impl IntoResponse {
        vb.render(AddSet(name, vb.user.clone(), 0))
    }

    #[derive(Serialize, Deserialize)]
    struct AddSetAction {
        name: String,
        reps: u16,
    }

    async fn add_set_action(
        vb: Vibe,
        user: User,
        db: Database,
        Json(json): Json<AddSetAction>,
    ) -> Result<impl IntoResponse> {
        let _set: Set = db
            .insert(Set {
                id: ulid!(),
                user_id: user.id.clone(),
                name: json.name,
                reps: json.reps,
                weight: 0,
                created_at: now(),
            })
            .await?;
        let sets = db.sets_for_user(&user).await?;

        vb.redirect_to(ForYou(&user, &sets), Route::ForYou)
    }

    #[derive(Routes, Debug)]
    pub enum Route {
        #[get("/")]
        Index,

        #[get("/login")]
        Login,

        #[post("/login")]
        LoginAction,

        #[post("/logout")]
        Logout,

        #[get("/signup")]
        Signup,

        #[post("/signup")]
        SignupAction,

        #[get("/for-you")]
        ForYou,

        #[get("/add-set/:name")]
        AddSet(String),

        #[post("/add-set")]
        AddSetAction,

        #[get("/profile")]
        Profile,
    }

    #[derive(Debug, Serialize, Deserialize, Default)]
    pub struct Set {
        pub id: String,
        pub user_id: String,
        pub name: String,
        pub reps: u16,
        pub weight: u16,
        pub created_at: u64,
    }
}

#[allow(unused)]
#[cfg(feature = "frontend")]
mod frontend {
    use crate::{
        circle_button, display_value, html, input_reps, Hx, Markup, Push, Route, Swap, Target,
    };
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
        let Push { digit } = serde_json::from_str::<Push>(&request.body)
            .expect("could not parse value from request body");
        let reps = *REPS.lock().unwrap();
        match push_digit(reps, digit) {
            Some(new_reps) => {
                *REPS.lock().unwrap() = new_reps;
                html! {
                    (display_value(new_reps))
                    (input_reps(new_reps, true))
                }
            }
            None => html! {
                (display_value(reps))
                (input_reps(reps, true))
            },
        }
    }

    fn pop(_request: &Request) -> Markup {
        let reps = *REPS.lock().unwrap();
        match pop_digit(reps) {
            Some(new_reps) => {
                *REPS.lock().unwrap() = new_reps;
                html! {
                    (display_value(new_reps))
                    (input_reps(new_reps, true))
                }
            }
            None => html! {
                (display_value(reps))
                (input_reps(reps, true))
            },
        }
    }

    fn not_found(_request: &Request) -> Markup {
        html! { "not found" }
    }

    fn route(request: &Request) -> Markup {
        let handler = match request.path() {
            "/frontend/push" => push,
            "/frontend/pop" => pop,
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

#[derive(wasm_router::Routes, Serialize, Deserialize)]
pub enum Route {
    #[post("/frontend/push")]
    Push,
    #[post("/frontend/pop")]
    Pop,
}

pub fn circle_button(
    route: Hx,
    swap: Swap,
    target: Target,
    children: impl std::fmt::Display,
) -> Markup {
    html! {
        (button(route, swap, target, CIRCLE_BUTTON, children))
    }
}
#[derive(Clone, Copy, Default)]
pub enum Target {
    Body,
    Display,
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
            Target::This => "this",
            Target::Display => "display",
            Target::Body => "body",
        })
    }
}

impl Target {
    fn selector(&self) -> String {
        match self {
            Target::Body => "body",
            Target::Display => "#display",
            Target::This => "this",
        }
        .into()
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
    Fs(String),
    Axum(String),
    Http(String),
}

pub fn input_reps(reps: u16, swap_oob: bool) -> Markup {
    let hx_swap_oob = match swap_oob {
        true => Some("outerHTML:.js-reps"),
        false => None,
    };
    html! {
        input class="js-reps" hx-swap-oob=[hx_swap_oob] type="hidden" name="reps" value=(reps);
    }
}

pub fn display_value(reps: u16) -> Markup {
    html! {
        div id=(Target::Display) class="text-6xl" {
            (reps)
        }
    }
}

pub fn button(
    route: Hx,
    swap: Swap,
    target: Target,
    class: &str,
    children: impl std::fmt::Display,
) -> Markup {
    let target = format!("#{}", target);
    let hx_post = match route {
        Hx::Get(_) => None,
        Hx::Post(route) => Some(route),
    };

    let hx_get = match route {
        Hx::Get(route) => Some(route),
        Hx::Post(_) => None,
    };

    html! {
        button
            class=(class)
            hx-get=[hx_get]
            hx-post=[hx_post]
            hx-push-url=[hx_get]
            hx-swap=(swap)
            hx-target=(target) {
            (children)
        }
    }
}

pub enum Hx<'a> {
    Get(&'a dyn std::fmt::Display),
    Post(&'a dyn std::fmt::Display),
}

#[derive(Deserialize)]
pub struct Push {
    pub digit: u16,
}

impl Render for Push {
    fn render(&self) -> Markup {
        html! {
            form {
                input type="hidden" name="digit" value=(self.digit);
                button class=(CIRCLE_BUTTON) hx-post=(Route::Push) hx-swap=(Swap::OuterHTML) hx-target=(Target::Display.selector()) {
                    (self.digit)
                }
            }
        }
    }
}

pub mod class {
    pub const RECT_BUTTON: &'static str = "flex rounded-md bg-orange-500 active:bg-orange-700 text-white p-4 items-center justify-center uppercase w-full";
    pub const CIRCLE_BUTTON: &'static str = "flex rounded-full p-4 border dark:border-white border-slate-600 items-center justify-center border-2 w-20 h-20";
}
