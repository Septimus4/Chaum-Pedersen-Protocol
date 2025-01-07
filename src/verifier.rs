use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};

use chaum_pedersen::ZKP;

pub mod auth {
    include!("./auth.rs");
}

use auth::{
    auth_server::{Auth, AuthServer},
    CreateAuthenticationChallengeRequest, CreateAuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse, VerifyAuthenticationRequest, VerifyAuthenticationResponse,
};

#[derive(Debug, Default)]
pub struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserInfo>>,
    pub auth_id_to_user: Mutex<HashMap<String, String>>,
}

#[derive(Debug, Default)]
pub struct UserInfo {
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,

    pub r1: BigUint,
    pub r2: BigUint,

    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}


#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = "127.0.0.1:41337".to_string();

    println!("Running the server in {}", addr);

    let auth_impl = AuthImpl::default();
    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().unwrap())
        .await
        .unwrap();
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let request = request.into_inner();

        println!("Registration of user: {:?}", request.user);

        let user_info = UserInfo {
            user_name: request.user.clone(),
            y1: BigUint::from_bytes_be(&request.y1),
            y2: BigUint::from_bytes_be(&request.y2),
            ..Default::default()
        };

        let mut user_info_map = self.user_info.lock().unwrap();
        user_info_map.insert(request.user, user_info);

        println!("Registration successful");

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        request: Request<CreateAuthenticationChallengeRequest>,
    ) -> Result<Response<CreateAuthenticationChallengeResponse>, Status> {
        let request = request.into_inner();
        println!("Processing Challenge Request for user: {:?}", request.user);

        let mut user_info_map = self.user_info.lock().unwrap();
        match user_info_map.get_mut(&request.user) {
            Some(user_info) => {
                let (_, _, _, q) = ZKP::get_constants();
                let c = ZKP::generate_random_number_below(&q);
                let auth_id = ZKP::generate_random_string(12);

                user_info.c = c.clone();
                user_info.r1 = BigUint::from_bytes_be(&request.r1);
                user_info.r2 = BigUint::from_bytes_be(&request.r2);

                let mut auth_map = self.auth_id_to_user.lock().unwrap();
                auth_map.insert(auth_id.clone(), request.user.clone());

                println!("Challenge created");

                Ok(Response::new(CreateAuthenticationChallengeResponse {
                    auth_id,
                    c: c.to_bytes_be(),
                }))
            }
            None => Err(Status::new(
                Code::NotFound,
                format!("User '{}' not found", request.user),
            )),
        }
    }

    async fn verify_authentication(
        &self,
        request: Request<VerifyAuthenticationRequest>,
    ) -> Result<Response<VerifyAuthenticationResponse>, Status> {
        let request = request.into_inner();
        println!("Processing Challenge Solution for auth_id: {:?}", request.auth_id);

        let auth_map = self.auth_id_to_user.lock().unwrap();
        match auth_map.get(&request.auth_id) {
            Some(user_name) => {
                let mut user_info_map = self.user_info.lock().unwrap();
                let user_info = user_info_map
                    .get_mut(user_name)
                    .ok_or_else(|| {
                        Status::new(
                            Code::NotFound,
                            format!("AuthId '{}' not found", request.auth_id),
                        )
                    })?;

                user_info.s = BigUint::from_bytes_be(&request.s);

                let (alpha, beta, p, q) = ZKP::get_constants();
                let zkp = ZKP { alpha, beta, p, q };
                let verified = zkp.verify(
                    &user_info.r1,
                    &user_info.r2,
                    &user_info.y1,
                    &user_info.y2,
                    &user_info.c,
                    &user_info.s,
                );

                if verified {
                    let session_id = ZKP::generate_random_string(12);
                    println!("Solution correct for user: {:?}", user_name);

                    Ok(Response::new(VerifyAuthenticationResponse { session_id }))
                } else {
                    println!("Solution incorrect for user: {:?}", user_name);
                    Err(Status::new(
                        Code::PermissionDenied,
                        format!("AuthId '{}' has an incorrect challenge solution", request.auth_id),
                    ))
                }
            }
            None => Err(Status::new(
                Code::NotFound,
                format!("AuthId '{}' not found", request.auth_id),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auth::{
        auth_client::AuthClient,
        CreateAuthenticationChallengeRequest, RegisterRequest, VerifyAuthenticationRequest,
    };
    use chaum_pedersen::ZKP;
    use num_bigint::{BigUint, RandBigInt};
    use rand::thread_rng;
    use std::net::TcpListener;
    use tokio::time::{sleep, Duration};
    use tonic::transport::Server;
    use tonic::Request;

    /// Spawn the gRPC server on a random free port and return (full_uri, JoinHandle).
    async fn spawn_server() -> (String, tokio::task::JoinHandle<()>) {
        // 1) Bind a standard TcpListener to an ephemeral port
        let std_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local_addr = std_listener.local_addr().unwrap(); // e.g. 127.0.0.1:54321
        let full_uri = format!("http://{}", local_addr);

        // 2) Convert to AuthImpl
        let auth_impl = AuthImpl::default();

        // 3) Spawn the server in the background
        let handle = tokio::spawn(async move {
            // We don’t need serve_with_incoming — just serve the `local_addr`
            // The server will keep running until the test finishes and drops the JoinHandle
            Server::builder()
                .add_service(AuthServer::new(auth_impl))
                .serve(local_addr)
                .await
                .expect("server failed");
        });

        // 4) Return the address + the join handle
        (full_uri, handle)
    }

    #[tokio::test]
    async fn test_end_to_end_auth_flow() -> Result<(), Box<dyn std::error::Error>> {
        // --------------------------------------------------
        // 1) Spawn our gRPC server on a random port
        // --------------------------------------------------
        let (server_addr, _join_handle) = spawn_server().await;

        // Give the server a moment to actually start listening
        sleep(Duration::from_millis(100)).await;

        // --------------------------------------------------
        // 2) Create a client for our Auth service
        // --------------------------------------------------
        let mut client = AuthClient::connect(server_addr).await?;

        // For convenience, create a ZKP struct
        let (alpha, beta, p, q) = ZKP::get_constants();
        let zkp = ZKP { alpha, beta, p, q };

        // --------------------------------------------------
        // 3) REGISTER the user
        // --------------------------------------------------
        let x = thread_rng().gen_biguint_below(&zkp.q); // user’s secret
        let y1 = zkp.alpha.modpow(&x, &zkp.p);
        let y2 = zkp.beta.modpow(&x, &zkp.p);

        let user_name = "alice".to_string();
        let register_request = RegisterRequest {
            user: user_name.clone(),
            y1: y1.to_bytes_be(),
            y2: y2.to_bytes_be(),
        };
        client.register(Request::new(register_request)).await?;
        println!("--- Registered user: {} ---", user_name);

        // --------------------------------------------------
        // 4) CREATE AUTHENTICATION CHALLENGE
        // --------------------------------------------------
        let k = thread_rng().gen_biguint_below(&zkp.q); // ephemeral
        let (r1, r2) = zkp.compute_pair(&k);

        let challenge_req = CreateAuthenticationChallengeRequest {
            user: user_name.clone(),
            r1: r1.to_bytes_be(),
            r2: r2.to_bytes_be(),
        };
        let challenge_resp = client
            .create_authentication_challenge(Request::new(challenge_req))
            .await?
            .into_inner();

        let auth_id = challenge_resp.auth_id;
        let c = BigUint::from_bytes_be(&challenge_resp.c);
        println!("--- Created challenge for user: {} / auth_id: {} ---", user_name, auth_id);

        // --------------------------------------------------
        // 5) SOLVE AND VERIFY AUTHENTICATION
        // --------------------------------------------------
        // Solve: s = k - c*x (mod q)
        let s = zkp.solve(&k, &c, &x);

        let verify_req = VerifyAuthenticationRequest {
            auth_id: auth_id.clone(),
            s: s.to_bytes_be(),
        };
        let verify_resp = client.verify_authentication(Request::new(verify_req)).await;

        match verify_resp {
            Ok(resp) => {
                let session_id = resp.into_inner().session_id;
                assert!(!session_id.is_empty(), "Session ID should not be empty");
                println!("--- Auth succeeded! Session ID: {} ---", session_id);
            }
            Err(e) => panic!("Auth verification failed with error: {:?}", e),
        }

        // Test completes and drops the JoinHandle — the server stops
        Ok(())
    }
}