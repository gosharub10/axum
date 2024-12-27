use std::{env::VarError, error::Error, fmt::Display};

use serde::Serialize;
use serde_json::json;

#[derive(Debug, Serialize,Clone)]
pub enum Errors {
    IO(String),
    Axum(String),
    Sqlx(String),
    Env(String)
}

impl From<VarError> for Errors {
    fn from(v: VarError) -> Self {
        Errors::Env(v.to_string())
    }
}

impl From<sqlx::Error> for Errors {
    fn from(v: sqlx::Error) -> Self {
        Errors::Sqlx(v.to_string())
    }
}

impl From<axum::Error> for Errors {
    fn from(v: axum::Error) -> Self {
        Errors::Axum(v.to_string())
    }
}

impl From<std::io::Error> for Errors {
    fn from(v: std::io::Error) -> Self {
        Errors::IO(v.to_string())
    }
}

impl Display for Errors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Errors::IO(error) => {
                let json_string = json!({ "error": error}).to_string();
                write!(f, "{}", json_string)
            }
            Errors::Axum(error) => {
                let json_string = json!({ "error": error}).to_string();
                write!(f, "{}", json_string)
            }
            Errors::Sqlx(error) => {
                let json_string = json!({"error": error}).to_string();
                write!(f,"{}", json_string)
            },
            Errors::Env(error) => {
                let json_string = json!({"error": error}).to_string();
                write!(f,"{}", json_string)
            },
        }
    }
}

impl Error for Errors {}
