use maud::{html, Markup};
use serde::{Deserialize, Serialize};

fn main() {
    #[cfg(feature = "backend")]
    match backend::main() {
        Ok(_) => {}
        Err(err) => panic!("{}", err),
    }
}

#[cfg(feature = "backend")]
#[allow(unused)]
pub mod backend {
    use crate::{
        button, circle_button, display_value, ok_button, Error, Exercise, Hx, PushForm, Swap,
        Target,
    };
    use axum::{
        async_trait,
        extract::{rejection::TypedHeaderRejection, FromRequestParts, Path, State},
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
    use rizz::{asc, desc, eq, r#in, Connection, Integer, JournalMode, Table, Text};
    use serde::{de::DeserializeOwned, Deserialize, Serialize};
    use std::{collections::HashMap, sync::OnceLock};

    macro_rules! id {
        () => {{
            ulid::Ulid::new().to_string()
        }};
    }

    #[tokio::main]
    pub async fn main() -> Result<()> {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
        let db = db().await;
        let _ = db.migrate().await?;

        let addr = "127.0.0.1:9006".parse().unwrap();
        println!("Listening on localhost:9006");
        Server::bind(&addr).serve(routes()).await.unwrap();
        Ok(())
    }

    fn routes() -> IntoMakeService<Router> {
        Route::router()
            .layer(middleware::from_fn(csp_middleware))
            .into_make_service()
    }

    #[derive(Serialize, Deserialize)]
    struct GetAddReps {
        exercise_name: String,
        exercise_id: String,
        user_id: String,
        reps: u16,
        digit: u16,
    }

    impl Render for GetAddReps {
        fn render(&self) -> Markup {
            html! {
                div class="flex flex-col gap-8 px-4 lg:px-0" {
                    div class="text-center text-2xl" {
                        (self.exercise_name)
                    }
                    div class="border rounded-xl flex justify-between items-end p-4" {
                        div class="text-md" { "reps" }
                        (display_value(self.reps))
                    }
                    div class="grid grid-rows-4 grid-cols-3 gap-4 mx-auto" {
                        @for digit in 1..=9 {
                            (PushForm { digit })
                        }
                        (circle_button(Hx::Post(&"/frontend/pop"), Swap::OuterHTML, Target::Display, "del"))
                        (PushForm { digit: 0 })
                        @if self.user_id.is_empty() {
                            (ok_button(0))
                        } @else {
                            (ok_button(0))
                        }
                    }
                }
            }
        }
    }

    impl GetAddReps {
        async fn get(vb: Vibe, db: Database, user: User, Path(path): Path<GetAddReps>) -> Html {
            let ex = db.exercise_by_id(path.exercise_id).await?;
            let get_add_reps = GetAddReps {
                exercise_name: ex.name,
                exercise_id: ex.id,
                user_id: user.id,
                reps: path.reps,
                digit: path.digit,
            };

            vb.render(get_add_reps)
        }
    }

    struct PostAddReps;

    impl PostAddReps {
        async fn post(vb: Vibe) -> Html {
            vb.render(html! {})
        }
    }

    struct Profile;
    impl Profile {
        async fn get(vibe: Vibe, user: User) -> Result<impl IntoResponse> {
            vibe.render(profile_component(user))
        }
    }

    struct ExerciseList;

    impl ExerciseList {
        async fn get(vibe: Vibe, db: Database) -> Result<impl IntoResponse> {
            let exercises = db.exercises().await?;
            vibe.render(exercises_component(exercises))
        }
    }

    async fn create_set_form_response(
        State(_): State<Database>,
        vb: Vibe,
        user: User,
        db: Database,
        Json(params): Json<AddSetForm>,
    ) -> Result<impl IntoResponse> {
        let ex: Exercise = db.exercise_by_id(params.exercise_id).await?;
        vb.render(EnterReps {
            exercise_id: ex.id,
            exercise_name: ex.name,
            reps: 0,
            user_id: user.id,
        })
    }

    impl From<AddSetForm> for Set {
        fn from(value: AddSetForm) -> Self {
            Set {
                id: id!(),
                user_id: "".into(),
                reps: value.reps,
                exercise_id: value.exercise_id.clone(),
                weight: 0,
                created_at: now(),
            }
        }
    }

    // async fn add_set_response(
    //     vb: Vibe,
    //     db: Database,
    //     user: User,
    //     Json(params): Json<AddSetForm>,
    // ) -> Result<impl IntoResponse> {
    //     let mut set = Set::from(params);
    //     set.user_id = user.id.clone();
    //     let _set: Set = db.insert(set).await?;
    //     let sets = db.sets_for_user(user).await?;

    //     Ok((
    //         AppendHeaders([("Hx-Push-Url", Route::Sets.url())]),
    //         vb.render(SetsComponent { sets }),
    //     ))
    // }

    fn signup_form_component(reps: u16) -> Markup {
        html! {}
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

    fn static_files() -> Vec<Markup> {
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
                @for static_file in static_files() {
                    (static_file)
                }
                title { "do u even lift bro?" }
                meta content="text/html;charset=utf-8" http-equiv="Content-Type";
                meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no";
                meta charset="UTF-8";
            }
        }
    }

    fn nav(user: Option<&User>) -> Markup {
        html! {
            div class="text-2xl py-4 mb-4 bg-indigo-500 text-white text-center flex justify-center gap-4 max-w-md" {
                (nav_link(Route::Index, Swap::InnerHTML, Target::Body, "home"))
                @if let None = user {
                    (nav_link(Route::GetSignup { reps: 0 }, Swap::InnerHTML, Target::Body, "signup"))
                } @else {
                    (nav_link(Route::ExerciseList, Swap::InnerHTML, Target::Body, "add set"))
                    (nav_link(Route::SetList, Swap::InnerHTML, Target::Body, "sets"))
                    (nav_button(Route::Logout, Swap::InnerHTML, Target::Body, "logout"))
                }
            }
        }
    }

    fn body(user: Option<&User>, children: impl Render) -> Markup {
        html! {
            body id="body" class="h-screen dark:bg-gray-950 dark:text-white max-w-lg mx-auto" hx-ext="json-enc" {
                (nav(user))
                (children)
            }
        }
    }

    #[allow(unused)]
    enum SameSite {
        Lax,
        Strict,
        None,
    }

    struct CookieOptions {
        name: String,
        value: String,
        http_only: bool,
        max_age: u64,
        same_site: SameSite,
        secure: bool,
        path: String,
    }

    struct Logout;
    impl Logout {
        async fn post(vb: Vibe, user: User, db: Database) -> Result<impl IntoResponse> {
            let pushups = db.exercise_by_name("standard push-ups").await?;
            let new_set = EnterReps {
                exercise_id: pushups.id,
                exercise_name: pushups.name,
                reps: 0,
                user_id: user.id,
            };
            let headers = AppendHeaders([(SET_COOKIE, "id=")]);
            Ok((
                AppendHeaders([(
                    SET_COOKIE,
                    format!("id=; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",),
                )]),
                vb.render(new_set),
            ))
        }
    }

    struct SetList;

    impl SetList {
        async fn get(vb: Vibe, db: Database, user: User) -> Result<impl IntoResponse> {
            let set_exercises = db.sets_with_exercise_for_user(user).await?;
            vb.render(GetSets { set_exercises })
        }
    }

    struct Index;

    impl Index {
        async fn get(vb: Vibe, db: Database) -> Html {
            let Exercise {
                id: exercise_id,
                name: exercise_name,
                ..
            } = db.exercise_by_name("standard push-ups").await?;

            let new_set = GetAddReps {
                digit: 0,
                user_id: vb.user.as_ref().unwrap_or(&User::default()).id.clone(),
                exercise_id,
                exercise_name,
                reps: 0,
            };

            vb.render(new_set)
        }
    }

    impl Render for GetLogin {
        fn render(&self) -> Markup {
            html! {
                div class="flex flex-col gap-8 text-center pt-4 px-4 lg:px-0 max-w-sm mx-auto" {
                    form {
                        input type="text" name="secret";
                        (rect_button(Hx::Get(&Route::GetLogin), Swap::InnerHTML, Target::Body, "get back to working out"))
                    }
                    (link(Route::GetSignup { reps: 0 }, Swap::InnerHTML, Target::Body, "click here to signup"))
                }
            }
        }
    }

    struct GetLogin;

    impl GetLogin {
        async fn get(vb: Vibe) -> Result<impl IntoResponse> {
            vb.render(Self {})
        }
    }

    #[derive(Serialize, Deserialize)]
    struct PostLogin {
        secret: String,
    }

    impl PostLogin {
        async fn post(
            vb: Vibe,
            db: Database,
            Json(params): Json<Self>,
        ) -> Result<impl IntoResponse> {
            let maybe_user = db.user_by_secret(params.secret).await;

            match maybe_user {
                Ok(user) => {
                    let session: Session = db
                        .insert(Session {
                            id: id!(),
                            user_id: user.id,
                            created_at: now(),
                        })
                        .await?;

                    let pushups = db.exercise_by_name("standard push-ups").await?;
                    let new_set = EnterReps {
                        exercise_id: pushups.id,
                        exercise_name: pushups.name,
                        reps: 0,
                        user_id: "".into(),
                    };

                    Ok((
                        AppendHeaders([(
                            SET_COOKIE,
                            format!(
                            "id={}; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",
                            session.id
                        ),
                        )]),
                        vb.render(new_set),
                    )
                        .into_response())
                }
                Err(err) => match err {
                    Error::NotFound => Ok(vb.render(GetLogin {}).into_response()),
                    _ => Err(err.into()),
                },
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    struct GetSignup {
        reps: u16,
    }

    impl GetSignup {
        async fn get(vb: Vibe, Path(params): Path<GetSignup>) -> Result<impl IntoResponse> {
            vb.render(GetSignup { reps: params.reps })
        }
    }

    impl Render for GetSignup {
        fn render(&self) -> Markup {
            html! {
                div class="flex flex-col gap-6 pt-4 px-4 lg:px-0 max-w-sm mx-auto" {
                    (PostSignup { reps: self.reps })
                    (link(Route::GetLogin, Swap::InnerHTML, Target::Body, "click here if you already have an account"))
                }
            }
        }
    }

    impl Render for PostSignup {
        fn render(&self) -> Markup {
            html! {
                form {
                    input type="hidden" name="reps" value=(self.reps);
                    (rect_button(Hx::Post(&Route::PostSignup), Swap::InnerHTML, Target::Body, "track your workout right now"))
                }
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    struct PostSignup {
        reps: u16,
    }

    impl PostSignup {
        async fn post(
            vb: Vibe,
            db: Database,
            Json(params): Json<PostSignup>,
        ) -> Result<impl IntoResponse> {
            // create user
            let user: User = db
                .insert(User {
                    id: id!(),
                    secret: id!(),
                    created_at: now(),
                })
                .await?;
            let user_id = user.id.clone();
            // create session
            let session: Session = db
                .insert(Session {
                    id: id!(),
                    user_id: user_id.clone(),
                    created_at: now(),
                })
                .await?;
            // grab pushups
            let ex = db.exercise_by_name("standard push-ups").await?;
            // create set with given reps
            let set: Set = db
                .insert(Set {
                    id: id!(),
                    exercise_id: ex.id,
                    user_id,
                    reps: params.reps,
                    weight: 0,
                    created_at: now(),
                })
                .await?;
            // list all sets for user
            let set_exercises = db.sets_with_exercise_for_user(user).await?;
            // render GetSets
            // set session cookie
            let headers = AppendHeaders([(
                SET_COOKIE,
                format!(
                    "id={}; HttpOnly; Max-Age=34560000; SameSite=Strict; Secure; Path=/",
                    session.id
                ),
            )]);
            let body = vb.render(GetSets { set_exercises });

            Ok((headers, body))
        }
    }

    fn now() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now();
        now.duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    async fn signup_response(
        vb: Vibe,
        db: Database,
        Json(params): Json<AddSetForm>,
    ) -> Result<impl IntoResponse> {
        let user: User = db
            .insert(User {
                id: id!(),
                secret: id!(),
                created_at: now(),
            })
            .await?;

        let session: Session = db
            .insert(Session {
                id: id!(),
                user_id: user.id.clone(),
                created_at: now(),
            })
            .await?;

        let pushups = db.exercise_by_name("standard push-ups").await?;

        let _set = db
            .insert::<Set>(Set {
                id: id!(),
                user_id: user.id.clone(),
                exercise_id: pushups.id,
                reps: params.reps,
                weight: 0,
                created_at: now(),
            })
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
                (rect_button(Hx::Get(&Route::ExerciseList), Swap::InnerHTML, Target::Body, "add another set"))
            }
        }
    }

    struct File;
    impl File {
        async fn get(uri: Uri) -> impl IntoResponse {
            StaticFile(uri.path().to_string())
        }
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

    #[derive(Clone)]
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

            let user = match user {
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
                exercises,
            } = *self;
            let _ = db
                .create_table(users)
                .create_table(sessions)
                .create_table(exercises)
                .create_unique_index(exercises, vec![exercises.name])
                .create_table(sets)
                .migrate()
                .await?;

            let maybe_ex = db
                .select()
                .from(exercises)
                .limit(1)
                .first::<Exercise>()
                .await;

            if let Err(rizz::Error::RowNotFound) = maybe_ex {
                let rows = std::fs::read_to_string("./exercises.csv")
                    .expect("exercises.csv doesn't exist");
                for line in rows.split("\n") {
                    let name = line.trim();
                    let _rows = db
                        .insert(exercises)
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

        async fn insert<T: Serialize + DeserializeOwned + Sync + Send + 'static>(
            &self,
            record: impl Into<Record>,
        ) -> Result<T> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
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
                Record::Exercise(new_exercise) => {
                    let row = db
                        .insert(exercises)
                        .values(new_exercise)?
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
            let exercises = Exercises::new();
            Database {
                db,
                users,
                sessions,
                sets,
                exercises,
            }
        }

        async fn exercise_by_name(&self, name: &str) -> Result<Exercise> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
            } = *self;
            let row = db
                .select()
                .from(exercises)
                .r#where(eq(exercises.name, name))
                .limit(1)
                .first()
                .await?;
            Ok(row)
        }

        async fn user_by_secret(&self, secret: String) -> Result<User> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
            } = *self;
            let row = db
                .select()
                .from(users)
                .r#where(eq(users.secret, secret))
                .first::<User>()
                .await?;
            Ok(row)
        }

        async fn sets_with_exercise_for_user(&self, user: User) -> Result<Vec<SetExercise>> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
            } = *self;
            let sets = db
                .select()
                .from(sets)
                .r#where(eq(sets.user_id, user.id.clone()))
                .limit(30)
                .order(vec![desc(sets.created_at)])
                .all::<Set>()
                .await?;

            /*
                ['select * from "sets" where "sets"."user_id" = ? limit 30 order by "sets"."created_at" desc', "\"drop table rboer;"]
            */
            // select *
            // from

            let ids = sets.iter().map(|s| &s.exercise_id).collect::<Vec<_>>();
            let exs = db
                .select()
                .from(exercises)
                .r#where(r#in(exercises.id, ids))
                .all::<Exercise>()
                .await?;

            let exs = exs
                .into_iter()
                .map(|ex| (ex.clone().id, ex))
                .collect::<HashMap<String, Exercise>>();

            let sets: Vec<SetExercise> = sets
                .into_iter()
                .map(|set| {
                    if let Some(exercise) = exs.get(&set.exercise_id) {
                        SetExercise {
                            set,
                            exercise: exercise.clone(),
                        }
                    } else {
                        SetExercise {
                            set,
                            exercise: Exercise::default(),
                        }
                    }
                })
                .collect::<Vec<_>>();

            Ok(sets)
        }

        async fn user_by_session_id(&self, session_id: &str) -> Result<User> {
            // TODO: this should be a transaction or a join
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
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

        async fn exercises(&self) -> Result<Vec<Exercise>> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
            } = *self;

            let rows: Vec<Exercise> = db
                .select()
                .from(exercises)
                .order(vec![asc(exercises.name)])
                .all()
                .await?;
            Ok(rows)
        }

        async fn exercise_by_id(&self, exercise_id: String) -> Result<Exercise> {
            let Self {
                ref db,
                users,
                sessions,
                sets,
                exercises,
            } = *self;

            let row: Exercise = db
                .select()
                .from(exercises)
                .r#where(eq(exercises.id, exercise_id))
                .first()
                .await?;
            Ok(row)
        }
    }

    impl Vibe {
        fn render(&self, children: impl Render) -> Html {
            Ok(html! {
                (DOCTYPE)
                html {
                    (head())
                    (body(self.user.as_ref(), children))
                }
            })
        }
    }

    async fn db() -> Database {
        static DB: OnceLock<Database> = OnceLock::new();
        let db = Connection::new("db.sqlite3")
            .create_if_missing(true)
            .journal_mode(JournalMode::Wal)
            .foreign_keys(true)
            .open()
            .await
            .expect("Could not connect to database")
            .database();

        DB.get_or_init(|| Database::new(db)).clone()
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
            let db = db().await;
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
            parts: &mut axum::http::request::Parts,
            state: &S,
        ) -> std::result::Result<Self, Self::Rejection> {
            let db = db().await;

            Ok(db)
        }
    }

    pub fn rect_button(
        route: Hx,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            (button(route, swap, target, "flex rounded-md bg-indigo-500 hover:bg-indigo-600 active:bg-indigo-700 text-white p-4 items-center justify-center uppercase", children))
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
                a class="text-indigo-500 hover:text-indigo-600 active:text-indigo-700 hover:underline" hx-get=(self.route) hx-target=(self.target) hx-swap=(self.swap) hx-push-url=(self.route) {
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
            a class="text-indigo-500 hover:text-indigo-600 active:text-indigo-700 hover:underline" hx-get=(route) hx-target=(target) hx-swap=(swap) hx-push-url=(route) { (children) }
        }
    }

    pub fn button_link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            button class="text-indigo-500 hover:text-indigo-600 active:text-indigo-700 hover:underline" hx-post=(route) hx-target=(target) hx-swap=(swap) hx-push-url=(route) { (children) }
        }
    }

    pub fn exercises_component(exs: Vec<Exercise>) -> Markup {
        html! {
            div class="text-2xl text-center h-screen" {
                div class="flex flex-col gap-4 divide divide-y dark:divide-gray-700" {
                    @for ex in exs {
                        div class="flex gap-4" {
                            (Link {
                                route: Route::GetAddReps { exericse_id: ex.id },
                                swap: Swap::InnerHTML,
                                target:Target::Body,
                                children: ex.name
                            })
                        }
                    }
                }
            }
        }
    }

    pub fn nav_link(
        route: Route,
        swap: Swap,
        target: Target,
        children: impl std::fmt::Display,
    ) -> Markup {
        html! {
            a class="hover:text-indigo-900 active:text-indigo-700 hover:underline cursor-pointer"
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
            a class="hover:text-indigo-900 active:text-indigo-700 hover:underline cursor-pointer"
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

    type Result<T> = std::result::Result<T, Error>;

    pub enum Record {
        Set(Set),
        User(User),
        Session(Session),
        Exercise(Exercise),
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

    impl From<Exercise> for Record {
        fn from(ex: Exercise) -> Self {
            Record::Exercise(ex)
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
        exercises: Exercises,
    }

    struct EnterReps {
        exercise_id: String,
        exercise_name: String,
        reps: u16,
        user_id: String,
    }

    impl Render for EnterReps {
        fn render(&self) -> Markup {
            html! {}
        }
    }

    pub struct GetSets {
        set_exercises: Vec<SetExercise>,
    }

    impl Render for GetSets {
        fn render(&self) -> Markup {
            html! {
                div class="text-2xl text-center h-screen" {
                    div class="flex flex-col gap-4 divide divide-y dark:divide-gray-700" {
                        @for s in &self.set_exercises {
                            div class="flex gap-4" {
                                p { (s.exercise.name) }
                                p { (s.set.reps) " reps" }
                            }
                        }
                    }
                }
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    struct AddSetForm {
        exercise_id: String,
        reps: u16,
        children: String,
    }

    impl maud::Render for AddSetForm {
        fn render(&self) -> Markup {
            html! {
                form {
                    input type="hidden" name="children" value="";
                    input class="js-reps" type="hidden" name="reps" value=(self.reps);
                    input type="hidden" name="exercise_id" value=(self.exercise_id);
                    (PreEscaped(self.children.clone()))
                }
            }
        }
    }

    #[derive(Routes, Serialize, Deserialize)]
    pub enum Route {
        #[get("/")]
        Index,
        #[get("/profile")]
        Profile,
        #[get("/login")]
        GetLogin,
        #[post("/login")]
        PostLogin,
        #[post("/logout")]
        Logout,
        #[get("/static/*file")]
        File,
        // #[default]
        // #[route("/404")]
        // NotFound,
        #[get("/set-list")]
        SetList,
        #[get("/exercise-list")]
        ExerciseList,
        #[get("/add-reps/:exercise_id")]
        GetAddReps { exericse_id: String },
        #[post("/add-reps")]
        PostAddReps,
        #[get("/signup/:reps")]
        GetSignup { reps: u16 },
        #[post("/signup")]
        PostSignup,
    }

    #[derive(Serialize, Deserialize, Default)]
    pub struct Set {
        pub id: String,
        pub user_id: String,
        pub exercise_id: String,
        pub reps: u16,
        pub weight: u16,
        pub created_at: u64,
    }

    struct SetExercise {
        set: Set,
        exercise: Exercise,
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

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Exercise {
    pub id: String,
    pub name: String,
    pub created_at: u64,
}

fn ok_button(reps: u16) -> Markup {
    html! {
        span class="js-reps" hx-swap-oob="outerHTML:.js-reps" {
            (circle_button(Hx::Get(&format!("/signup/{}", reps)), Swap::InnerHTML, Target::Body, "ok"))
        }
    }
}

pub fn display_value(reps: u16) -> Markup {
    html! {
        div id=(Target::Display) class="text-6xl" {
            (reps)
        }
        // input class="js-reps" type="hidden" name="reps" value=(reps) hx-swap-oob="outerHTML:button[hx-post^='/signup/']";
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

pub fn circle_button(
    route: Hx,
    swap: Swap,
    target: Target,
    children: impl std::fmt::Display,
) -> Markup {
    html! {
        (button(route, swap, target, "flex rounded-full p-4 border dark:border-white border-slate-600 items-center justify-center border-2 w-20 h-20", children))
    }
}

#[derive(Deserialize)]
struct PushForm {
    digit: u16,
}

impl maud::Render for PushForm {
    fn render(&self) -> Markup {
        html! {
            form {
                input type="hidden" name="digit" value=(self.digit);
                (circle_button(Hx::Post(&"/frontend/push"), Swap::OuterHTML, Target::Display, self.digit))
            }
        }
    }
}

#[cfg(feature = "frontend")]
mod frontend {
    use crate::{display_value, html, ok_button, Markup, PushForm};
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
        let PushForm { digit } = serde_json::from_str::<PushForm>(&request.body)
            .expect("could not parse value from request body");
        let reps = *REPS.lock().unwrap();
        match push_digit(reps, digit) {
            Some(new_reps) => {
                *REPS.lock().unwrap() = new_reps;
                html! {
                    (display_value(new_reps))
                    (ok_button(new_reps))
                }
            }
            None => html! {
                (display_value(reps))
                (ok_button(reps))
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
                    (ok_button(reps))
                }
            }
            None => html! {
                (display_value(reps))
                (ok_button(reps))
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
