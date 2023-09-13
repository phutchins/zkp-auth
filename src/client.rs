pub mod params;
pub mod zkp_auth;
pub mod utils;

use std::{env, io};
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::Num;
use tonic::{Response, Status};
use tonic::transport::Channel;
use params::{public};
use utils::{mod_exp_fast, random_big_int};

use zkp_auth:: auth_client::{AuthClient};
use zkp_auth::{
  RegisterRequest,
  RegisterResponse,
  AuthenticationChallengeRequest,
  AuthenticationChallengeResponse,
  AuthenticationAnswerRequest,
  AuthenticationAnswerResponse
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>>{
  // TODO: Move this to env variable so that it is easily set by docker-compose
  //let addr: String = String::from("http://[::1]:8080");
  // Open a channel to the server
  let mut client = get_client().await?;

  // Import public parameters from params.rs
  let (p, q, g, h) = public();

  let command_line_args = get_args();

  // Empty command line args or register
  match command_line_args.len() {
    1 => {
      println!("Please use one of the following commands: register | login");
    }
    2 => {
      let cmd = &command_line_args[1];
      match &cmd[..] {
        "register" => {
          println!("Registering...");
          let (user, pw_bytes) = get_user_credentials();
          let (y1, y2) = generate_register_params(&p, &g, &h, &pw_bytes);
          zkp_register(&mut client, user, y1, y2).await.expect("TODO: panic message");
        }
        "login" => {
          println!("Logging in...");
          let (user, pw_bytes) = get_user_credentials();
          let (r1, r2) = generate_login_params(&p, &g, &h, &pw_bytes);
          zkp_login(&mut client, user, pw_bytes, r1, r2, &q).await.expect("TODO: panic message");
        }
        _ => {
          println!("Please use one of the following commands: register | login");
        }
      }
    }
    _ => {
      println!("Got too many arguments {}", command_line_args.len());
      println!("Please use one of the following commands: register | login");
    }
  };

  Ok(())
}

async fn get_client() -> Result<AuthClient<Channel>, tonic::transport::Error>{
  // Open a channel to the server
  //let addr: String = String::from("http://[::1]:8080");
  let channel = Channel::from_static("http://[::1]:8080")
    .connect().await?;

  // Create a client using the channel we just created
  let client = AuthClient::new(channel);
  Ok(client)
}

// Get the command line arguments passed to the program
fn get_args() -> Vec<String>{
  let args: Vec<String> = env::args().collect();
  args
}

// Get the users credentials from the command line
fn get_user_credentials() -> (String, BigInt){
  let mut username = String::new();
  let mut password = String::new();

  println!("Please input username:");
  io::stdin()
    .read_line(&mut username)
    .expect("Failed to read username");

  println!("Please input password:");
  io::stdin()
    .read_line(&mut password)
    .expect("Failed to read password");

  let pw_bytes = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());

  (username, pw_bytes)
}

// Generate the register request to send to the server
fn generate_register_params(p: &BigInt, g: &i32, h: &i32, pw_bytes: &BigInt) -> (String, String){
  let y1 = mod_exp_fast(&g.to_bigint().unwrap(), &pw_bytes, &p).to_str_radix(16);
  let y2 = mod_exp_fast(&h.to_bigint().unwrap(), &pw_bytes, &p).to_str_radix(16);
  (y1, y2)
}

// Register a new user with the zkp auth server
async fn zkp_register(client: &mut AuthClient<Channel>, user: String, y1: String, y2: String) -> Result<Response<RegisterResponse>, Status>{
  let register_request = tonic::Request::new(
    RegisterRequest {
      user,
      y1,
      y2
    }
  );
  println!("Sending register request: {:?}", register_request);

  let register_response = client.register(register_request).await?;

  println!("Response: {:?}", register_response);
  Ok(register_response)
}

// Generate the login parameters to send to the server
fn generate_login_params(p: &BigInt, g: &i32, h: &i32, pw_bytes: &BigInt) -> (String, String){
  let r1 = mod_exp_fast(&g.to_bigint().unwrap(), &pw_bytes, &p).to_str_radix(16);
  let r2 = mod_exp_fast(&h.to_bigint().unwrap(), &pw_bytes, &p).to_str_radix(16);
  (r1, r2)
}

// Login a user with the zkp auth server
async fn zkp_login(client: &mut AuthClient<Channel>, user: String, pw_bytes: BigInt, r1: String, r2: String, q: &BigInt) -> Result<Response<AuthenticationChallengeResponse>, Status>{
  // Generate a random big int in {2, ..., q - 2}
  let k = random_big_int(2.to_bigint().unwrap(), q - 2);

  // Create the authentication challenge request
  let authentication_challenge_request = tonic::Request::new(
    AuthenticationChallengeRequest {
      user,
      r1,
      r2
    }
  );
  // Send the authentication challenge request to the server
  let authentication_challenge_response = client.create_authentication_challenge(authentication_challenge_request).await?;
  // Grab the auth_id which is the identifier for the user on the server
  let auth_id = &authentication_challenge_response.get_ref().auth_id;

  println!("Authentication challenge response: {:?}", authentication_challenge_response);

  // Get the challenge from the response
  let c: BigInt = Num::from_str_radix(
    &authentication_challenge_response.get_ref().c, 16).unwrap();

  // Compute the answer to the challenge
  let s = (((&k - &c * &pw_bytes) % (q)) + (q)) & (q);

  // Create the authentication answer request
  let authentication_answer_request = tonic::Request::new(
    AuthenticationAnswerRequest {
      auth_id: auth_id.to_string(),
      s: s.to_str_radix(16)
    }
  );

  // Verify the authentication answer with the server
  let authentication_answer_response: Response<AuthenticationAnswerResponse> = client.verify_authentication(authentication_answer_request).await?;

  // Get the session id from the response
  let session_id = &authentication_answer_response.get_ref().session_id;

  if session_id == "auth_fail"{
    println!("Authentication failed");
  }
  else{
    println!("Authentication successful");
  }

  Ok(authentication_challenge_response)
}