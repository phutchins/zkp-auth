use warp::Filter;
use num_bigint::{BigInt, ToBigInt};
use num_traits::{Zero, One};
use num::pow;


#[tokio::main]
async fn main() {
    // GET /hello/warp => 200 OK with body "Hello, warp!"
    let hello = warp::path!("hello" / String)
        .map(|name| format!("Hello, {}!", name));

    //test_it().await;

    warp::serve(hello)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

async fn test_it() {
    // Create public parameters
    // Big int from 2^2048-2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
    // let p = BigInt::from_str_radix("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
    //    020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51\
    //    C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF", 16).unwrap();
    let p = 10009.to_bigint().unwrap();
    let q = (p.clone() - 1.to_bigint().unwrap()) / 2.to_bigint().unwrap();

    println!("p (large prime) = {}", &p);
    println!("q (p - 1 / 2) = {}", &q);

    let g = 2.to_bigint().unwrap();
    let h = 4.to_bigint().unwrap();

    println!("g = {}", &g);
    println!("h = {}", &h);

    let a = 10.to_bigint().unwrap();
    let b = 12.to_bigint().unwrap();

    println!("a = {}", &a);
    println!("b = {}", &b);

    //let A = mod_exp(&g, &a, &p);
    //let B = mod_exp(&g, &b, &p);
    let r: u32 = 10;
    //let A = pow(&g, &r) % &p;
    let A = mod_exp(&h, &r.to_bigint().unwrap(), &p);
    println!("A = {}", &A);
    println!("r = {}", &r);
    //let A = BigInt::pow(&g, 10u32) % &p;

    println!("A = {}", &A);
    //println!("B = {}", &B);

    let c = (a.clone() * b.clone()) % p.clone();

    println!("c = {}", &c);
}

pub fn mod_exp(g: &BigInt, x: &BigInt, q: &BigInt) -> BigInt {

    let one: BigInt = One::one();
    let zero: BigInt = Zero::zero();
    let two: BigInt = &one + &one;

    if q == &one { return zero }
    println!("q = {}", q);
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