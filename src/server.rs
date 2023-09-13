pub mod params;
pub mod utils;
mod zkp_auth;
use tonic::{transport::Server, Request, Response, Status};
//use num_bigint::BigInt;

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
/*
use utils::{
  mod_exp_fast
};*/

#[derive(Default)]
pub struct AuthZKP {}

#[tonic::async_trait]
impl Auth for AuthZKP {
  async fn register(&self, request:Request<RegisterRequest>) -> Result<Response<RegisterResponse>, Status> {
    println!("Request={:?}", request);
    println!("Registering user...");
    println!("Params={:?}", public());
    Ok(Response::new(RegisterResponse{}))
  }

  async fn create_authentication_challenge(&self, request:Request<AuthenticationChallengeRequest>) -> Result<Response<AuthenticationChallengeResponse>, Status> {
    let auth_id = String::new();
    let c = String::new();

    println!("Request: {:?}", request);

    Ok(Response::new(AuthenticationChallengeResponse{
      auth_id: auth_id,
      c: c,
    }))
  }

  async fn verify_authentication(&self, request:Request<AuthenticationAnswerRequest>) -> Result<Response<AuthenticationAnswerResponse>, Status> {
    let mut session_id = String::new();

    // tmp
    session_id = "auth_fail".to_string();

    println!("Request: {:?}", request);
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
pub fn insert_into_store(store: &mut scdb::Store, key: &str, value: &str){
  let b_key = key.as_bytes();
  let b_value = value.as_bytes();
  store.set(&b_key[..], &b_value[..], None).unwrap();
}

// A function to get a value from the store
pub fn get_from_store(store: &mut scdb::Store, key: &str) -> String{
  // Convert key to bytes
  let b_key = key.as_bytes();

  let result = store.get(&b_key[..]).unwrap().unwrap();
  bytes_to_string(result)
}

// A function to delete a key value pair from the store
pub fn delete_from_store(store: &mut scdb::Store, key: &str){
  let b_key = key.as_bytes();
  store.delete(&b_key,).unwrap();
}

// A function to check if a key exists in the store
pub fn key_exists(store: &mut scdb::Store, key: &str) -> bool{
  let b_key = key.as_bytes();
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

  let mut store = new_store();
  insert_into_store(&mut store, "test", "test");

  let addr = "[::1]:8080".parse().unwrap();
  let auth = AuthZKP::default();

  Server::builder()
    .add_service(AuthServer::new(auth))
    .serve(addr)
    .await?;

  println!("Server listening on {}", addr);

  Ok(())
}