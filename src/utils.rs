use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{Zero, One};

pub fn mod_exp_fast(g: &BigInt, x: &BigInt, q: &BigInt) -> BigInt {

  let one: BigInt = One::one();
  let zero: BigInt = Zero::zero();
  let two: BigInt = &one + &one;

  if q == &one { return zero } // Can't have exponent less than one so return zero
  // println!("q = {}", q);
  let mut result = 1.to_bigint().unwrap();

  println!("result = {}", result);
  let mut base = g % q;
  println!("base = g({}) % q({}) = {}", g, q, base);
  let mut exp = x.clone();
  while &exp > &zero {
    if &exp % &two == one {
      result = result * &base % q;
      println!("result = (result * base) % q = {}", result);
    }
    println!("before: exp = {}", exp);
    exp = exp >> 1;
    println!("after: exp = {}", exp);
    base = &base * &base % q;
    println!("new base = (base * base) % q = {}", base);
  }

  (result + q) % q
}

// Generate a random BigInt
pub fn random_big_int(from: BigInt, to: BigInt) -> BigInt {
  rand::thread_rng().gen_bigint_range(&from, &to)
}