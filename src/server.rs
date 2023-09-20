pub mod params;
pub mod utils;
mod zkp_auth;
mod logger;

use num_bigint::{ToBigInt};
use num_traits::Num;
use tonic::{transport::Server, Request, Response, Status};
use num_bigint::BigInt;
use log::{info, debug, error};
use zkp_auth:: auth_server::{Auth, AuthServer};
use zkp_auth::{
  RegisterRequest,
  RegisterResponse,
  AuthenticationChallengeRequest,
  AuthenticationChallengeResponse,
  AuthenticationAnswerRequest,
  AuthenticationAnswerResponse
};
use params::{public, get_server_bind_addr};
use crate::utils::{mod_exp_fast, random_big_int};

#[derive(Default)]
pub struct AuthZKP {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  logger::init().expect("Failed to initialize logger");

  let addr = get_server_bind_addr();
  info!("Starting ZKP API server on {}...", addr);

  let auth = AuthZKP::default();

  Server::builder()
    .add_service(AuthServer::new(auth))
    .serve((addr).parse().unwrap())
    .await?;

  Ok(())
}

#[tonic::async_trait]
impl Auth for AuthZKP {
  async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
    // Get store
    let mut store = new_store();

    // Get user and y1, y2 (str_radix(16) encoded)
    let user = &request.get_ref().user;
    let y1 = &request.get_ref().y1;
    let y2 = &request.get_ref().y2;

    // Check if user is already registered
    let user_is_registered = key_exists(&mut store, user, "y1");

    info!("user_is_registered = {}", user_is_registered);
    if user_is_registered == false {
      // Insert user into store
      store_y_vals(user, &y1, &y2).await;

      debug!("Just insert y1 - {}", y1);
      debug!("Just insert y2 - {}", y2);
      Ok(Response::new(RegisterResponse{}))
    } else {
      info!("User already registered");
      Err(Status::invalid_argument("User already registered"))
    }
  }

  //
  async fn create_authentication_challenge(&self, request:Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
    let mut store = new_store();


    let q = public().1;
    let user = &request.get_ref().user;
    let r1 = &request.get_ref().r1;
    let r2 = &request.get_ref().r2;

    info!("Got authentication challenge request");
    debug!("r1 = {}", &r1);
    debug!("r2 = {}", &r2);
    debug!("user = {}", &user);

    let c: BigInt = generate_c(&q);
    let user_registered = key_exists(&mut store, user, "y1");

    let auth_id = if user_registered {
      // TODO: Hash the username later
      user.to_string()
    } else {
      "UserNotRegistered".to_string()
    };

    if user_registered {
      // Insert r1 and r2 into store
      store_r_vals(user, &r1, &r2).await;
      store_c_val(user, &c);
    } else {
      error!("User not registered");
      return Err(Status::invalid_argument("User not registered"));
    }

    Ok(Response::new(AuthenticationChallengeResponse{
      auth_id,
      c: c.to_str_radix(16),
    }))
  }

  async fn verify_authentication(&self, request:Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
    let mut session_id = "auth_fail".to_string();
    let mut store = new_store();

    // Get the solution to the challenge from the client
    let s_raw = &request.get_ref().s;
    let s: BigInt = Num::from_str_radix(s_raw, 16).unwrap();
    debug!("Got solution to challenge: {}", &s);

    // Get y1, y2, r2, r2 from data store
    let user = &request.get_ref().auth_id;
    let (y1, y2) = get_y_vals_from_store(user).await;
    let (r1, r2 ) = get_r_vals_from_store(user).await;

    //let c_raw = get_from_store(&mut store, user, "c").unwrap();
    //let c: BigInt = Num::from_str_radix(&c_raw, 16).unwrap();
    let c: BigInt = get_c_val_from_store(user);

    // Delete the commitment from the store
    delete_from_store(&mut store, user, "r1");
    delete_from_store(&mut store, user, "r2");

    let auth_successful = do_verify_calc(&y1, &y2, &r1, &r2, &c, &s);

    // Compare validators results to prover results
    if auth_successful {
      info!("Authentication successful");
      // TODO: Generate and store an actual session_id
      session_id = "auth_success".to_string();
    } else {
      info!("Authentication failed");
    }

    debug!("Session id: {:?}", session_id);

    Ok(Response::new(AuthenticationAnswerResponse{
      session_id
    }))
  }
}

async fn get_y_vals_from_store(user: &str) -> (BigInt, BigInt){
  let mut store = new_store();

  let y1 = get_from_store(&mut store, user, "y1").unwrap();
  let y2 = get_from_store(&mut store, user, "y2").unwrap();

  let y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
  let y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();

  (y1, y2)
}

async fn get_r_vals_from_store(user: &str) -> (BigInt, BigInt){
  let mut store = new_store();

  let r1 = get_from_store(&mut store, user, "r1").unwrap();
  let r2 = get_from_store(&mut store, user, "r2").unwrap();

  let r1: BigInt = Num::from_str_radix(&r1, 16).unwrap();
  let r2: BigInt = Num::from_str_radix(&r2, 16).unwrap();

  (r1, r2)
}

async fn store_y_vals(user: &str, y1: &String, y2: &String){
  let mut store = new_store();

  insert_into_store(&mut store, user, "y1", &y1);
  insert_into_store(&mut store, user, "y2", &y2);
}

async fn store_r_vals(user: &str, r1: &String, r2: &String){
  let mut store = new_store();

  insert_into_store(&mut store, user, "r1", &r1);
  insert_into_store(&mut store, user, "r2", &r2);
}

fn generate_c(q: &BigInt) -> BigInt {
  let lower_bound = 2.to_bigint().unwrap();
  let upper_bound = q - 1;
  let c = random_big_int(&lower_bound, &upper_bound);
  debug!("Generated challenge for authenticator: {}", &c);
  c
}

fn store_c_val(user: &str, c: &BigInt){
  let mut store = new_store();
  let c_str: String = c.to_str_radix(16);
  insert_into_store(&mut store, user, "c", &c_str);
}

fn get_c_val_from_store(user: &str) -> BigInt{
  let mut store = new_store();
  let c = get_from_store(&mut store, user, "c").unwrap();
  let c: BigInt = Num::from_str_radix(&c, 16).unwrap();
  c
}

// TODO: Make this return values so that we can test it
pub fn do_verify_calc(y1: &BigInt, y2: &BigInt, r1: &BigInt, r2: &BigInt, c: &BigInt, s: &BigInt) -> bool{
  let (p, _q, g, h) = public();

  // Compute the results
  // R1 = g^2 * y1^c
  // R2 = h^s * y2^c
  let result1 = (mod_exp_fast(&g.to_bigint().unwrap(), &s, &p ) * mod_exp_fast(&y1, &c, &p)) % &p;
  let result2 = (mod_exp_fast(&h.to_bigint().unwrap(), &s, &p ) * mod_exp_fast(&y2, &c, &p)) % &p;

  debug!("r1 = {}", &r1);
  debug!("result1 = {}", &result1);
  debug!("r2 = {}", &r2);
  debug!("result2 = {}", &result2);

  if &result1 == r1 && &result2 == r2 {
    true
  } else {
    false
  }
}

// A function to create a new SCDB store and return the store
pub fn new_store() -> scdb::Store{
  let store = scdb::Store::new("db",
  Some(1000),
  Some(1),
  Some(10),
  Some(1800),
  true).unwrap();

  store
}

// A function to insert a new key value pair into the store
pub fn insert_into_store(store: &mut scdb::Store, prefix: &str, key: &str, value: &str){
  let prefix_key = format!("{}-{}", prefix, key);
  let b_key = prefix_key.as_bytes();
  let b_value = value.as_bytes();

  // Convert b_key to a printable string
  let b_key_string = bytes_to_string(b_key.to_vec());
  let b_value_string = bytes_to_string(b_value.to_vec());
  debug!("Inserting into store - key: {:?} value: {:?}", b_key_string, b_value_string);
  store.set(&b_key[..], &b_value[..], None).unwrap();
}

// A function to get a value from the store
pub fn get_from_store(store: &mut scdb::Store, prefix: &str, key: &str) -> Result<String, &'static str>{
  let prefix_key = format!("{}-{}", prefix, key);
  let b_key = prefix_key.as_bytes();
  let result = store.get(&b_key);
  match result {
    Ok(None) => Err("Error getting value from store"),
    Ok(Some(value)) => {
      let b_value = value;
      let b_value_string = bytes_to_string(b_value.to_vec());
      Ok(b_value_string)
    },
    _ => {
      error!("Error getting value from store");
      Err("Error getting value from store")
    }
  }
}

// A function to delete a key value pair from the store
pub fn delete_from_store(store: &mut scdb::Store, prefix: &str, key: &str){
  let prefix_key = format!("{}-{}", prefix, key);
  let b_key = prefix_key.as_bytes();

  store.delete(&b_key,).unwrap();
}

// A function to check if a key exists in the store
pub fn key_exists(store: &mut scdb::Store, prefix: &str, key: &str) -> bool{
  let prefix_key = format!("{}-{}", prefix, key);
  let b_key = prefix_key.as_bytes();

  let b_key_string = bytes_to_string(b_key.to_vec());
  debug!("Checking if key exists: {:?}", b_key_string);

  let result = store.get(&b_key).unwrap();
  match result {
    Some(_) => true,
    None => false,
  }
}

// Function to convert a vector of bytes to a string
pub fn bytes_to_string(bytes: Vec<u8>) -> String{
  let result = String::from_utf8(bytes).unwrap();
  result
}

#[cfg(test)]
mod tests{
  use num_bigint::ToBigInt;

  #[test]
  fn test_mod_exp_fast(){
    let g = 4.to_bigint().unwrap();
    let x = 10.to_bigint().unwrap();
    let p = 23.to_bigint().unwrap();

    let result = super::mod_exp_fast(&g, &x, &p);

    assert_eq!(result, 6.to_bigint().unwrap());
  }

  #[test]
  fn test_create_authentication_challenge() {

  }
}