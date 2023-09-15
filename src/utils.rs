use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{Zero, One};
use num_traits::{cast::FromPrimitive};
pub fn mod_exp_fast2(mut b: BigInt, mut e: BigInt, m: BigInt) -> BigInt
{
  let mut result = BigInt::from_u64(1).unwrap();
  let big1 = BigInt::from_u64(1).unwrap();
  let big2 = BigInt::from_u64(2).unwrap();
  while e > BigInt::from_u64(0).unwrap()
  {
    if e.clone() % big2.clone() == big1
    {
      result = (result.clone() * b.clone()) % m.clone();
    }
    b = (b.clone() * b.clone()) % m.clone();
    e = e.clone() / 2.clone();
  }
  result % m
}

pub fn mod_exp_fast(g: &BigInt, x: &BigInt, q: &BigInt) -> BigInt {

  let one: BigInt = One::one();
  let zero: BigInt = Zero::zero();
  let two: BigInt = &one + &one;

  if q == &one { return zero } // Can't have exponent less than one so return zero
  // println!("q = {}", q);
  let mut result = 1.to_bigint().unwrap();

  //println!("result = {}", result);
  let mut base = g % q;
  //println!("base = g({}) % q({}) = {}", g, q, base);
  let mut exp = x.clone();
  while &exp > &zero {
    if &exp % &two == one {
      result = result * &base % q;
      //println!("result = (result * base) % q = {}", result);
    }
    //println!("before: exp = {}", exp);
    exp = exp >> 1;
    //println!("after: exp = {}", exp);
    base = &base * &base % q;
    //println!("new base = (base * base) % q = {}", base);
  }

  (result + q) % q
}

// Generate a random BigInt
pub fn random_big_int(from: BigInt, to: BigInt) -> BigInt {
  rand::thread_rng().gen_bigint_range(&from, &to)
}