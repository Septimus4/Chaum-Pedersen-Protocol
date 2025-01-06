use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

use zkp_chaum_pedersen::ZKP;

#[tonic::async_trait]
async fn register() -> Result<Response<RegisterResponse>, Status> {
    let response = RegisterResponse {
        message: "Register".to_string(),
    };
    Ok(Response::new(response))
}
async fn create_authentication_challenge(
) -> Result<Response<CreateAuthenticationChallengeResponse>, Status> {
    let response = CreateAuthenticationChallengeResponse {
        message: "CreateAuthenticationChallenge".to_string(),
    };
    Ok(Response::new(response))
}
async fn verify_authentication() -> Result<Response<VerifyAuthenticationResponse>, Status> {
    let response = VerifyAuthenticationResponse {
        message: "VerifyAuthentication".to_string(),
    };
    Ok(Response::new(response))
}

#[tokio::main]
async fn main() {}
