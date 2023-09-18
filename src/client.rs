extern crate core;

pub mod params;
pub mod zkp_auth;
pub mod utils;

use std::{env, io};
use std::io::Write;
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::Num;
use rpassword::read_password;
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
          let (user, secret) = get_user_credentials();
          let pw_bytes = secret.clone();
          println!("pw_bytes as string: {}", pw_bytes);
          let (y1, y2) = generate_register_params(&p, &g, &h, &secret);
          zkp_register(&mut client, user, y1, y2).await.expect("TODO: panic message");
        }
        "login" => {
          println!("Logging in...");
          let (user, secret) = get_user_credentials();
          let (r1, r2, k) = generate_login_params(&g, &h, &p, &q);
          println!("Sending login request with values: ");
          println!("r1 = {}", &r1);
          println!("r2 = {}", &r2);
          println!("k = {}", &k);
          println!("user = {}", &*user);

          zkp_login(&mut client, user, &secret, r1, r2, q, k).await.expect("TODO: panic message");
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
  // TODO: Fix usage of addr from variable!
  //let addr: String = "http://[::1]:8080".parse().unwrap();
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

  print!("Please input username:");
  io::stdout().flush().unwrap();
  io::stdin()
    .read_line(&mut username)
    .expect("Failed to read username");

  print!("Please input password:");
  io::stdout().flush().unwrap();
  let mut password = read_password().unwrap();

  // Remove newlines from username and password
  username = username.trim().to_string();
  password = password.trim().to_string();

  // Convert the password to a number so that we can use it in calculations
  let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
  println!("secret as bigint: {}", secret);

  (username, secret)
}

// Generate the register request to send to the server
fn generate_register_params(p: &BigInt, g: &i32, h: &i32, secret: &BigInt) -> (String, String){
  println!("y1 = {}^{} mod {}", &g, &secret, &p);
  println!("y1 = {}", mod_exp_fast(&g.to_bigint().unwrap(), &secret, &p));
  println!("y2 = {}", mod_exp_fast(&h.to_bigint().unwrap(), &secret, &p));
  //println!("y2 = {}", mod_exp_fast(&h.to_bigint().unwrap(), &pw_bytes, &p));
  let y1 = mod_exp_fast(&g.to_bigint().unwrap(), &secret, &p).to_str_radix(16);
  let y2 = mod_exp_fast(&h.to_bigint().unwrap(), &secret, &p).to_str_radix(16);
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
fn generate_login_params(g: &i32, h: &i32, p: &BigInt, q: &BigInt) -> (BigInt, BigInt, BigInt){
  // Generate a random big int in {2, ..., q - 2}
  let k = random_big_int(2.to_bigint().unwrap(), q - 2);
  println!("r1 = g({})^k({}) mod p({})", &g, &k, &p);
  println!("r2 = h({})^k({}) mod p({})", &h, &k, &p);
  println!("k = {}", &k);
  let r1 = mod_exp_fast(&g.to_bigint().unwrap(), &k, &p);
  let r2 = mod_exp_fast(&h.to_bigint().unwrap(), &k, &p);
  (r1, r2, k)
}

// Login a user with the zkp auth server
async fn zkp_login(client: &mut AuthClient<Channel>, user: String, secret: &BigInt, r1: BigInt, r2: BigInt, q: BigInt, k: BigInt) -> Result<Response<AuthenticationChallengeResponse>, Status>{
  // Create the authentication challenge request
  let authentication_challenge_request = generate_auth_challenge_request(user.clone(), r1.clone(), r2.clone());
  /*
  let authentication_challenge_request = tonic::Request::new(
    AuthenticationChallengeRequest {
      user: user.clone(),
      r1: r1.to_str_radix(16),
      r2: r2.to_str_radix(16),
    }
  );
  */

  println!("Sending authentication challenge request");
  println!("r1 = {}", &r1);
  println!("r2 = {}", &r2);
  println!("user = {}", &*user);

  // Send the authentication challenge request to the server
  let authentication_challenge_response = client.create_authentication_challenge(authentication_challenge_request).await?;
  // Grab the auth_id which is the identifier for the user on the server
  let auth_id = &authentication_challenge_response.get_ref().auth_id;

  println!("Got auth_id: {}", auth_id);
  println!("Got challenge: {}", authentication_challenge_response.get_ref().c);

  //println!("Authentication challenge response: {:?}", authentication_challenge_response);

  // Get the challenge from the response
  let c: BigInt = Num::from_str_radix(
    &authentication_challenge_response.get_ref().c, 16).unwrap();

  // Compute the answer to the challenge
  //let s = (&k - &c * secret) % &q;
  let s = compute_s(&k, &c, secret, &q);
  println!("Solution {} - {} * {} mod {}", &k, &c, secret, &q);
  println!("Answer to challenge: {}", s);

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

fn generate_auth_challenge_request(user: String, r1: BigInt, r2: BigInt) -> AuthenticationChallengeRequest{
  AuthenticationChallengeRequest {
    user,
    r1: r1.to_str_radix(16),
    r2: r2.to_str_radix(16),
  }
}

fn compute_s(k: &BigInt, c: &BigInt, secret: &BigInt, q: &BigInt) -> BigInt{
  let s = (((*&k - *&c * secret) % (q)) + (q)) % (q);
  println!("Computing s = (( k({}) - c({}) * x({}) % q({}) + q({}) ) % q({})", &k, &c, secret, &q, &q, &q);
  //let s = (k - c * secret) % q;
  s
}

#[cfg(test)]
mod tests {
  use num_bigint::{BigInt, Sign, ToBigInt};
  use num_traits::Num;

  #[test]
  fn test_get_args() {
    let args = super::get_args();
    assert_eq!(args.len(), 1);
  }

  #[test]
  fn test_generate_register_params() {
    let password = "a".to_string();
    let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
    let (p, _q, g, h) = super::params::public();
    let (y1, y2) = super::generate_register_params(&p, &g, &h, &secret);
    let parsed_y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
    let parsed_y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();
    assert_eq!(parsed_y1, 13.to_bigint().unwrap());
    assert_eq!(parsed_y2, 2.to_bigint().unwrap());
    // TODO: Add tests with much larger params
  }

  #[test]
  fn test_generate_login_params() {
    let (p, q, g, h) = super::params::public();
    let (r1, r2, k) = super::generate_login_params(&g, &h, &p, &q);
    println!("Used random K value of {}", &k);
    assert_eq!(r1, 8.to_bigint().unwrap());
    assert_eq!(r2, 4.to_bigint().unwrap());
  }

  #[test]
  fn test_compute_s() {
    let (_p, q, _g, _h) = super::params::public();
    let k = 7.to_bigint().unwrap(); // TODO: Should generate random here?
    let c = 4.to_bigint().unwrap();
    let password = "a".to_string();
    let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
    let s = super::compute_s(&k, &c, &secret, &q);
    assert_eq!(s, 4.to_bigint().unwrap());
  }
}