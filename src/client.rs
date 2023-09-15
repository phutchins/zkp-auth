pub mod params;
pub mod zkp_auth;
pub mod utils;

use std::{env, io, str};
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::Num;
use num::pow::pow;
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
          println!("pw_bytes as string: {}", pw_bytes.to_str_radix(16));
          let (y1, y2) = generate_register_params(&p, &g, &h, &secret);
          zkp_register(&mut client, user, y1, y2).await.expect("TODO: panic message");
        }
        "login" => {
          println!("Logging in...");
          let (user, secret) = get_user_credentials();
          let (r1, r2) = generate_login_params(&p, &g, &h, &secret);
          zkp_login(&mut client, user, &secret, r1, r2, &q).await.expect("TODO: panic message");
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
  let mut password = String::new();

  println!("Please input username:");
  io::stdin()
    .read_line(&mut username)
    .expect("Failed to read username");

  println!("Please input password:");
  password = read_password().unwrap();

  println!("Got username: {}", username);
  println!("Got password: {}", password);

  // Remove newlines from username and password
  username = username.trim().to_string();
  password = password.trim().to_string();

  // Convert password to bytes (possibly unnecessary)
  //let pw_bytes = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
  // Convert password back to string
  //let pw_string = str::from_utf8(&pw_bytes).unwrap();
  //println!("Password as string: {}", pw_string);
  let pw_i32: i32 = password.parse().unwrap();
  //println!("Password as i32: {}", pw_i32);
  let pw_bi: BigInt = pw_i32.to_bigint().unwrap();
  //println!("Password as BigInt: {}", pw_bi);


  //let pw_as_bytes = password.as_bytes();
  //println!("pw_as_bytes: {:?}", pw_as_bytes);
  //let pw_big_int = BigInt::from_bytes_le(Sign::Plus, &pw_as_bytes);
  //println!("pw_big_int: {}", pw_big_int);
  //let pw_big_int_converted_back = pw_as_bytes.from_utf8().unwrap();
  //println!("pw_big_int_converted_back: {}", pw_big_int_converted_back);

  (username, pw_bi)
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
fn generate_login_params(g: &i32, h: &i32, k: &BigInt, p: &BigInt) -> (BigInt, BigInt){
  println!("r1 = g({})^k({}) mod p({})", &g, &k, &p);
  let r1 = mod_exp_fast(&g.to_bigint().unwrap(), &k, &p);
  let r2 = mod_exp_fast(&h.to_bigint().unwrap(), &k, &p);
  (r1, r2)
}

// Login a user with the zkp auth server
async fn zkp_login(client: &mut AuthClient<Channel>, user: String, pw_bytes: &BigInt, r1: String, r2: String, q: &BigInt) -> Result<Response<AuthenticationChallengeResponse>, Status>{
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

  println!("Got auth_id: {}", auth_id);

  //println!("Authentication challenge response: {:?}", authentication_challenge_response);

  // Get the challenge from the response
  let c: BigInt = Num::from_str_radix(
    &authentication_challenge_response.get_ref().c, 16).unwrap();

  // Compute the answer to the challenge
  let s = (((&k - &c * pw_bytes) % (q)) + (q)) & (q);
  //println!("Answer to challenge: {}", s.to_str_radix(16));

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