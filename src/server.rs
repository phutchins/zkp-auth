pub mod params;
pub mod utils;
mod zkp_auth;

use std::str::FromStr;
use num_bigint::{Sign, ToBigInt};
use num_traits::Num;
use tonic::{transport::Server, Request, Response, Status};
use num_bigint::BigInt;

use zkp_auth:: auth_server::{Auth, AuthServer};
use zkp_auth::{
  RegisterRequest,
  RegisterResponse,
  AuthenticationChallengeRequest,
  AuthenticationChallengeResponse,
  AuthenticationAnswerRequest,
  AuthenticationAnswerResponse
};

use params::{public};
use crate::utils::{mod_exp_fast, random_big_int};
/*
use utils::{
  mod_exp_fast
};*/

#[derive(Default)]
pub struct AuthZKP {}

#[tonic::async_trait]
impl Auth for AuthZKP {
  async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
    //println!("Request={:?}", request);
    //println!("Registering user...");
    //println!("Params={:?}", public());

    // Get store
    let mut store = new_store();

    // Get user and y1, y2
    let user = &request.get_ref().user;
    let y1 = &request.get_ref().y1;
    let y2 = &request.get_ref().y2;

    // Check if user is already registered
    let user_is_registered = key_exists(&mut store, user, "y1");

    if user_is_registered == false {
      // Insert user into store
      insert_into_store(&mut store, user, "y1", y1);
      insert_into_store(&mut store, user, "y2", y2);
    } else {
      // TODO: Return an error
      println!("User already registered");

      let user_y1 = get_from_store(&mut store, user, "y1");
      let user_y2 = get_from_store(&mut store, user, "y2");

      println!("User y1: {:?}", user_y1);
      println!("User y2: {:?}", user_y2);

      //Err(Status::invalid_argument("User already registered"));
    }

    Ok(Response::new(RegisterResponse{}))
  }

  async fn create_authentication_challenge(&self, request:Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
    let mut store = new_store();
    let mut auth_id = String::new();

    let q = public().1;
    let user = &request.get_ref().user;
    let r1 = &request.get_ref().r1;
    let r2 = &request.get_ref().r2;

    let c = random_big_int(2.to_bigint().unwrap(), &q - 1).to_str_radix(16);

    let user_registered = key_exists(&mut store, user, "y1");

    if user_registered == false {
      println!("User not registered");
      auth_id = "UserNotRegistered".to_string()
    } else {
      // TODO: Hash the username later
      auth_id = user.to_string();

      // Insert r1 and r2 into store
      insert_into_store(&mut store, user, "r1", r1);
      insert_into_store(&mut store, user, "r2", r2);
      insert_into_store(&mut store, user, "c", &c);
    }

    //println!("Request: {:?}", request);

    Ok(Response::new(AuthenticationChallengeResponse{
      auth_id: auth_id,
      c: c,
    }))
  }

  async fn verify_authentication(&self, request:Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
    let mut session_id = String::new();
    let mut store = new_store();

    // Get the solution to the challenge from the client
    let s_raw = &request.get_ref().s;
    let s: BigInt = Num::from_str_radix(s_raw, 16).unwrap();

    // Get y1, y2, r2, r2 from data store
    let user = &request.get_ref().auth_id;
    let y1 = get_from_store(&mut store, user, "y1").unwrap();
    let y2 = get_from_store(&mut store, user, "y2").unwrap();
    let r1 = get_from_store(&mut store, user, "r1").unwrap();
    let r2 = get_from_store(&mut store, user, "r2").unwrap();
    let c_raw = get_from_store(&mut store, user, "c").unwrap();
    let c: BigInt = Num::from_str_radix(&c_raw, 16).unwrap();

    // Delete the commitment from the store
    delete_from_store(&mut store, user, "r1");
    delete_from_store(&mut store, user, "r2");

    // Get the public params
    let (p, _q, g, h) = public();

    // Convert the strings to BigInts
    let y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
    let y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();
    let r1: BigInt = Num::from_str_radix(&r1, 16).unwrap();
    let r2: BigInt = Num::from_str_radix(&r2, 16).unwrap();

    // Compute the results
    // R1 = g^2 * y1^c
    //let result1 = g.pow(2) * y1.pow(u32::try_from(&c_big).unwrap()) % &p;
    // R2 = h^s * y2^c
    //let result2 = h.pow(2) * y2.pow(u32::try_from(&c_big).unwrap()) % &p;

    //let result1 = ((mod_exp_fast(&g.to_bigint().unwrap(), &s_big, &p) * mod_exp_fast(&y1, &c_big, &p) % &p) + &p) % &p;
    //let result2 = ((mod_exp_fast(&g.to_bigint().unwrap(), &s_big, &p) * mod_exp_fast(&y2, &c_big, &p) % &p) + &p) % &p;

    let result1 = ((mod_exp_fast(&g.to_bigint().unwrap(), &s, &p ) * mod_exp_fast(&y1, &c, &p)) + &p) % &p;
    let result2 = ((mod_exp_fast(&h.to_bigint().unwrap(), &s, &p ) * mod_exp_fast(&y2, &c, &p)) + &p) % &p;

    println!("r1 = {}", &r1);
    println!("result1 = {}", &result1);
    println!("r2 = {}", &r2);
    println!("result2 = {}", &result2);
    // Compare validators results to prover results
    if result1 == r1 && result2 == r2 {
      println!("Authentication successful");
      session_id = "auth_success".to_string();
    } else {
      println!("Authentication failed");
    }

    println!("Session id: {:?}", session_id);

    Ok(Response::new(AuthenticationAnswerResponse{
      session_id
    }))
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
  println!("Inserting into store - key: {:?} value: {:?}", b_key_string, b_value_string);
  store.set(&b_key[..], &b_value[..], None).unwrap();
}

// A function to get a value from the store
pub fn get_from_store(store: &mut scdb::Store, prefix: &str, key: &str) -> Result<String, &'static str>{
  // Convert key to bytes

  let prefix_key = format!("{}-{}", prefix, key);
  let b_key = prefix_key.as_bytes();

  let b_key_string = bytes_to_string(b_key.to_vec());
  //println!("b_key: {:?}", b_key_string);

  let result = store.get(&b_key);
  match result {
    Ok(None) => Err("Error getting value from store"),
    Ok(Some(value)) => {
      let b_value = value;
      let b_value_string = bytes_to_string(b_value.to_vec());
      //println!("b_value: {:?}", b_value_string);
      Ok(b_value_string)
    },
    _ => {
      println!("Error getting value from store");
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
  println!("Checking if key exists: {:?}", b_key_string);

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  println!("Starting ZKP API server...");

  let addr = "[::1]:8080".parse().unwrap();
  let auth = AuthZKP::default();

  Server::builder()
    .add_service(AuthServer::new(auth))
    .serve(addr)
    .await?;

  println!("Server listening on {}", addr);

  Ok(())
}