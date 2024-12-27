use std::{net::SocketAddr, sync::Arc};

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use error::Errors;
use serde::{Deserialize, Serialize};
use sqlx::{prelude::FromRow, PgPool};
use tracing::{info, Level};
use tracing_subscriber::fmt::format;

mod error;


#[derive(Clone)]
struct AppState{
    db: Arc<PgPool>
}

impl AppState {
    async  fn new(url: &str) -> Result<AppState, Errors> {
        let pool = sqlx::PgPool::connect(url).await?;

        info!("Database connection success!!!");

        Ok(AppState{
            db: Arc::new(pool)
        })
    }
}

#[derive(Serialize, Deserialize, FromRow)]
struct User{
    name : String,
    email: String,
    password: String,
    phone: String,
    address: String
}


#[tokio::main]
async fn main() -> Result<(), Errors>{
    let _ = dotenv::dotenv();

    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .event_format(format().compact())
        .init();

    let database_url = std::env::var("DATABASE_URL").map_err(|e| Errors::from(e));

    let app_state = AppState::new(&database_url?).await.map_err(|e| Errors::from(e));

    let app = Router::new()
        .route("/users", get(get_all))
        .route("/health_check", get(health_check))
        .with_state(app_state?);

    let addr = SocketAddr::from(([0,0,0,0], 3000));

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listner) => {
            info!("Server start on: http://0.0.0.0:3000");
            if let Err(err) = axum::serve(listner, app).await {
                tracing::error!("{}", Errors::from(err))
            }
        }
        Err(err) => {
            tracing::error!("{}", Errors::from(err))
        }
    }

    Ok(())
}

async fn health_check() -> impl IntoResponse{
    info!("Now it's running");
    StatusCode::OK
}

async fn get_all(State(db): State<AppState>) -> Result<impl IntoResponse ,(StatusCode, impl IntoResponse)>{
    let users = sqlx::query_as::<_, User>("SELECT * FROM users")
    .fetch_all(&*db.db)
    .await
    .map_err(|e|{
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("{}", Errors::from(e))
        )
    })?;

    Ok(Json(users))
}

//TODO сделать простейшие CRUD для работы с базой данных