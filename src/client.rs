extern crate core;

pub mod params;
pub mod zkp_auth;
pub mod utils;
mod logger;

use std::{env, io};
use std::io::Write;
use num_bigint::{BigInt, Sign, ToBigInt};
use num_traits::Num;
use rpassword::read_password;
use tonic::{Response, Status};
use tonic::transport::Channel;
use params::{public, get_server_addr};
use utils::{mod_exp_fast, random_big_int, get_client};
use log::{info, debug, error};

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
  logger::init().expect("Failed to initialize logger");
  // Open a channel to the server
  let server_addr = get_server_addr();
  let mut client = get_client(server_addr).await?;

  // Import public parameters from params.rs
  let (p, q, g, h) = public();

  // Read the args that the user entered on command line (register or login)
  let command_line_args = get_args();

  // Handle command line args
  match command_line_args.len() {
    1 => {
      info!("Please use one of the following commands: register | login");
    }
    2 => {
      let cmd = &command_line_args[1];
      match &cmd[..] {
        "register" => {
          info!("Registering...");
          let (user, secret) = get_user_credentials();
          let pw_bytes = secret.clone();
          debug!("pw_bytes as string: {}", pw_bytes);
          let (y1, y2) = generate_register_params(&p, &g, &h, &secret);
          let register_response = zkp_register(&mut client, user, y1, y2).await;
          match register_response {
            Ok(response) => {
              info!("Registration successful");
              info!("Response: {:?}", response);
            }
            Err(e) => {
              error!("Registration failed: {}", e.message());
              //return Err(Box::try_from(e).unwrap())
            }
          }
        }
        "login" => {
          info!("Logging in...");
          let (user, secret) = get_user_credentials();

          // Generate a random big int in {2, ..., q - 2}
          let lower_bound = 2.to_bigint().unwrap();
          let upper_bound = &q - 2;
          let k = random_big_int(&lower_bound, &upper_bound);
          let (r1, r2) = generate_login_params(&g, &h, &p, &k);
          debug!("Sending login request with values: ");
          debug!("r1 = {}", &r1);
          debug!("r2 = {}", &r2);
          debug!("k = {}", &k);
          debug!("user = {}", &*user);

          let login_response = zkp_login(&mut client, &user, &secret, &r1, &r2, &q, &k).await;
          match login_response {
            Ok(response) => {
              info!("Login successful! Session id: {}", response.get_ref().auth_id);
            }
            Err(e) => {
              error!("Login failed: {}", e.message());
            }
          }
        }
        _ => {
          error!("Please use one of the following commands: register | login");
        }
      }
    }
    _ => {
      error!("Got too many arguments {}", command_line_args.len());
      error!("Please use one of the following commands: register | login");
    }
  };

  Ok(())
}

// Get the command line arguments passed to the program
fn get_args() -> Vec<String>{
  let args: Vec<String> = env::args().collect();
  args
}

// Get the users credentials from the command line
fn get_user_credentials() -> (String, BigInt){
  let mut username = String::new();

  print!("Please input username: ");
  io::stdout().flush().unwrap();
  io::stdin()
    .read_line(&mut username)
    .expect("Failed to read username");

  print!("Please input password: ");
  io::stdout().flush().unwrap();
  let mut password = read_password().unwrap();

  // Remove newlines from username and password
  username = username.trim().to_string();
  password = password.trim().to_string();

  // Convert the password to a number so that we can use it in calculations
  let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
  debug!("secret as bigint: {}", secret);

  (username, secret)
}

// Generate the register request to send to the server
fn generate_register_params(p: &BigInt, g: &i32, h: &i32, secret: &BigInt) -> (String, String){
  debug!("y1 = {}^{} mod {}", &g, &secret, &p);
  debug!("y1 = {}", mod_exp_fast(&g.to_bigint().unwrap(), &secret, &p));
  debug!("y2 = {}", mod_exp_fast(&h.to_bigint().unwrap(), &secret, &p));
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
  debug!("Sending register request: {:?}", register_request);

  // Check register_response for an error and return it if there is one
  match client.register(register_request).await {
    Ok(response) => {
      debug!("Response: {:?}", response);
      Ok(response)
    }
    Err(e) => {
      debug!("Error: {}", e.message());
      return Err(e)
    }
  }
}

// Generate the login parameters to send to the server
fn generate_login_params(g: &i32, h: &i32, p: &BigInt, k: &BigInt) -> (BigInt, BigInt) {
  debug!("r1 = g({})^k({}) mod p({})", &g, &k, &p);
  debug!("r2 = h({})^k({}) mod p({})", &h, &k, &p);
  debug!("k = {}", &k);
  let r1 = mod_exp_fast(&g.to_bigint().unwrap(), &k, &p);
  let r2 = mod_exp_fast(&h.to_bigint().unwrap(), &k, &p);
  (r1, r2)
}

// Login a user with the zkp auth server
async fn zkp_login(client: &mut AuthClient<Channel>, user: &String, secret: &BigInt, r1: &BigInt, r2: &BigInt, q: &BigInt, k: &BigInt) -> Result<Response<AuthenticationChallengeResponse>, Status>{
  // Create the authentication challenge request
  let authentication_challenge_request = generate_auth_challenge_request(user.clone(), r1.clone(), r2.clone());

  debug!("Sending authentication challenge request");
  debug!("r1 = {}", &r1);
  debug!("r2 = {}", &r2);
  debug!("user = {}", &*user);

  // Send the authentication challenge request to the server
  let authentication_challenge_response = client.create_authentication_challenge(authentication_challenge_request).await?;
  // Grab the auth_id which is the identifier for the user on the server
  let auth_id = &authentication_challenge_response.get_ref().auth_id;

  debug!("Got auth_id: {}", auth_id);
  debug!("Got challenge: {}", authentication_challenge_response.get_ref().c);

  // Get the challenge from the response
  let c: BigInt = Num::from_str_radix(
    &authentication_challenge_response.get_ref().c, 16).unwrap();

  // Compute the answer to the challenge
  //let s = (&k - &c * secret) % &q;
  let s = compute_s(&k, &c, secret, &q);
  debug!("Solution {} - {} * {} mod {}", &k, &c, secret, &q);
  debug!("Answer to challenge: {}", s);

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

  if session_id != "auth_fail" {
    info!("Authentication successful");
    Ok(authentication_challenge_response)
  } else {
    error!("Authentication failed");
    let status = Status::unauthenticated("Authentication failed!");
    Err(status)
  }
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
  debug!("Computing s = (( k({}) - c({}) * x({}) % q({}) + q({}) ) % q({})", &k, &c, secret, &q,
    &q, &q);
  //let s = (k - c * secret) % q;
  s
}

#[cfg(test)]
mod tests {
  use std::str::FromStr;
  use num_bigint::{BigInt, Sign, ToBigInt};
  use num_traits::Num;

  #[test]
  fn test_get_args() {
    let args = super::get_args();
    assert_eq!(args.len(), 1);
  }

  #[test]
  fn test_random_big_int() {
    let min = 2.to_bigint().unwrap();
    let max = 10.to_bigint().unwrap();
    let random = super::random_big_int(&min, &max);
    assert!(random >= min);
    assert!(random <= max);
  }

  #[test]
  fn test_generate_register_params() {
    let expected_y1: &str = "158456325028528675187087900672";
    let expected_y2: &str = "25108406941546723055343157692830665664409421777856138051584";
    let password = "a".to_string();
    let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
    let (p, _q, g, h) = super::params::public();
    let (y1, y2) = super::generate_register_params(&p, &g, &h, &secret);
    let parsed_y1: BigInt = Num::from_str_radix(&y1, 16).unwrap();
    let parsed_y2: BigInt = Num::from_str_radix(&y2, 16).unwrap();
    assert_eq!(parsed_y1, BigInt::from_str(expected_y1).unwrap());
    assert_eq!(parsed_y2, BigInt::from_str(expected_y2).unwrap());
    // TODO: Add tests with much larger params
  }

  #[test]
  fn test_generate_login_params() {
    let expected_r1: &str =
      "8526010747860739536542910093130865013529064547597193796476139253441788684698780197039771461\
      39745974714043360719106241351388154384086108731348305337603900340539539181389627410893304459\
      98057722296239324181957390215432786159717519724237387292424094139529872693526867272888320995\
      23815471824982703272505216784049225696208389982887583579634383879474579092378927786936495752\
      80689620661793384509142894841094061060322972555232845147040228798467664064624700585066152596\
      01230230155726981318338394358428095366603233081364477929106788206737184233464086750137512552\
      98415698026141850686670725883944590389074269424556989860572102957";
    let expected_r2: &str =
      "2776970594256031669247410273345470541669363795648705199715214387511111273933923013187449452\
      09732703054359142627835897524455854280921589799918892573170217430425027603284530774195883717\
      56273832890072684757414954481564429052043658052311881506044203310558298306266548729945918812\
      69056657159636888913438723701955280949147501284807630040910261060822046217580032429726156544\
      99799748315647040179121671640943439396038676662963066202048636580001402569952788077737369909\
      30207248533773165182993783836213894461633022665146791367071270698772792083707282875039208115\
      068798994185108689281781252601161196976631484602804965380878276941";
    let not_so_random_k: &str =
      "1266082254487510560836086981573109935300525352354523279141360270552154041215530793884043691\
      21939574636737338018214360465192167646323477033214515238711269419307434243726070259516693283\
      88985318816078648813915197096947569949173572844494988743136230506006624808023145888782767359\
      64496477487567674986692938277377184147418344320899084863439448543929091116018324322461043798\
      33357025289058126461093381397810055545978197886765470812806075915255565407386346182224868061\
      49300073387048757928030128185126513548156642849919749042047244127844924345325726963097082513\
      8935357718236063074202831188919954770349396511975152992172985070";
    let (p, _q, g, h) = super::params::public();
    let (r1, r2) =
      super::generate_login_params(&g, &h, &p, &BigInt::from_str(not_so_random_k).unwrap());
    assert_eq!(r1, BigInt::from_str(expected_r1).unwrap());
    assert_eq!(r2, BigInt::from_str(expected_r2).unwrap());
  }

  #[test]
  fn test_compute_s() {
    let expected_result: &str = "16158503035655503650169456963211914124408970620570119556421004875\
    7003708533171771113098447086817846735589508689548520958773029366045975144268794930928110766060\
    8770625745088726013511789803911812444212309473879382055296432304970586162271331126109661527045\
    9518840262117759562839857935058500529027938825519430923640128988027451784866280763083540669680\
    8997706682382795801841589483645365891922948403198359504886010970843236129355157056682146597680\
    9673581826660485853872411399429428268460432264831803862513447775296418137556058704848649903420\
    5277179792433291645821068109115539495499724326234131208486017955926253522680544898";
    let (_p, q, _g, _h) = super::params::public();
    let k = 7.to_bigint().unwrap(); // TODO: Should generate random here?
    let c = 4.to_bigint().unwrap();
    let password = "a".to_string();
    let secret = BigInt::from_bytes_le(Sign::Plus, &password.as_bytes());
    let s = super::compute_s(&k, &c, &secret, &q);
    assert_eq!(s, BigInt::from_str(expected_result).unwrap());
  }
}