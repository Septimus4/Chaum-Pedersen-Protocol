use std::io::{self, stdin, Write};
use num_bigint::BigUint;
use tonic::transport::Channel;

pub mod auth {
    include!("./auth.rs");
}

use auth::{
    auth_client::AuthClient, CreateAuthenticationChallengeRequest, VerifyAuthenticationRequest,
    RegisterRequest,
};

use chaum_pedersen::ZKP;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (alpha, beta, p, q) = ZKP::get_constants();
    let zkp = ZKP { alpha, beta, p, q };

    let mut client = AuthClient::connect("http://127.0.0.1:41337").await?;
    println!("Connected to the server");

    let username = read_line("Please provide username: ")?;
    let password_registration = read_password("Please provide password: ")?;
    register_user(&mut client, &zkp, &username, &password_registration).await?;
    println!("Registration was successful");

    let password_auth = read_password("Please provide the password (to login): ")?;
    let session_id = authenticate_user(&mut client, &zkp, &username, &password_auth, &zkp.q).await?;
    println!("Login successful! session_id: {}", session_id);

    Ok(())
}

// -----------------------------------------------------------
// HELPER FUNCTIONS
// -----------------------------------------------------------

/// Reads a single line from stdin after printing a prompt.
/// Trims trailing whitespace/newlines.
fn read_line(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    // Ensure we flush stdout so user sees the prompt immediately
    io::stdout().flush()?;

    let mut buf = String::new();
    stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

/// Reads a password (or any secret-like input) from stdin after printing a prompt.
/// In a real CLI application, you might want to mask the input or use a secure method.
fn read_password(prompt: &str) -> io::Result<BigUint> {
    let input_str = read_line(prompt)?;
    // Convert user input to BigUint. In production, you'd handle invalid hex/base cases carefully.
    Ok(BigUint::from_bytes_be(input_str.as_bytes()))
}

/// Registers a user by sending `y1` and `y2` to the server.
async fn register_user(
    client: &mut AuthClient<Channel>,
    zkp: &ZKP,
    username: &str,
    password: &BigUint,
) -> Result<(), Box<dyn std::error::Error>> {
    let (y1, y2) = zkp.compute_pair(password);

    let request = RegisterRequest {
        user: username.to_string(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    // We don't need the response body if it's empty, just check for errors
    client.register(request).await?;
    Ok(())
}

/// Performs the authentication flow:
///  1) generate k, compute r1 = alpha^k mod p, r2 = beta^k mod p
///  2) request challenge (c)
///  3) solve for s = k - c*x mod q
///  4) send s back to get session_id
async fn authenticate_user(
    client: &mut AuthClient<Channel>,
    zkp: &ZKP,
    username: &str,
    password: &BigUint,
    q: &BigUint,
) -> Result<String, Box<dyn std::error::Error>> {
    // Generate ephemeral secret k
    let k = ZKP::generate_random_number_below(q);

    // Commitments
    let (r1, r2) = zkp.compute_pair(&k);

    let challenge_req = CreateAuthenticationChallengeRequest {
        user: username.to_string(),
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let challenge_resp = client
        .create_authentication_challenge(challenge_req)
        .await?
        .into_inner();

    let auth_id = challenge_resp.auth_id;
    let c = BigUint::from_bytes_be(&challenge_resp.c);

    // Solve for s = k - c*x mod q
    let s = zkp.solve(&k, &c, password);

    let verify_req = VerifyAuthenticationRequest {
        auth_id,
        s: s.to_bytes_be(),
    };

    let verify_resp = client.verify_authentication(verify_req).await?.into_inner();
    Ok(verify_resp.session_id)
}
