extern crate rand;
extern crate secp256k1;
extern crate libc;

use secp256k1::{Secp256k1,Message, Signature,Error};
use secp256k1::key::SecretKey;
use secp256k1::key::PublicKey;
use std::fmt::Write;
use libc::c_void;
use secp256k1::ffi;
use secp256k1::ffi::Context;
use std::time::Instant;

fn main() {
    let hash = "9f7f1c05ae72c53d27775fff84fc2ee6456f0dcc0958ca901813a0bb0e4e208f".from_hex().unwrap();
    let secret_key = "44d995141fbc30aa0d543b3e0ad2a8fe2cdc79eb53ac027506cbe5f73b065220".from_hex().unwrap();
    let secp = Secp256k1::new();
    let sk : SecretKey = SecretKey::from_slice(&secp,&secret_key[..]).unwrap();
    let pk : PublicKey = PublicKey::from_secret_key(&secp,&sk).unwrap();
    println!("{:?}",pk);
    let start = Instant::now();
    let mut i = 0u64;
    let mut shorter = 100;
    unsafe {
        let context = ffi::secp256k1_context_create(ffi::SECP256K1_START_SIGN | ffi::SECP256K1_START_VERIFY);

        loop {
            let message = Message::from_slice(&hash[..]).unwrap();
            let signature: Signature = sign(&message, &sk, &i, context).unwrap();
            let v = signature.serialize_der(&secp);
            if v.len()<shorter {
                let dur = start.elapsed();
                let secs : f64 = (dur.subsec_nanos() as f64 / 1_000_000_000f64)+dur.as_secs() as f64;
                shorter=v.len();
                println!("{} {} {:7.3}s {}",shorter,to_hex(v),secs,i);

            }
            i=i+1;
        }
    }

}

/// Encode the provided bytes into a hex string
pub fn to_hex(bytes: Vec<u8>) -> String {
    let mut s = String::new();
    for byte in bytes {
        write!(&mut s, "{:02x}", byte).expect("Unable to write");
    }
    s
}

/// Constructs a signature for `msg` using the secret key `sk` and RFC6979 nonce
    /// Requires a signing-capable context.
pub fn sign(msg: &Message, sk: &SecretKey, i: &u64, context: *mut Context)
            -> Result<Signature, Error> {

    let mut ret = unsafe { ffi::Signature::blank() };

    unsafe {
        // We can assume the return value because it's not possible to construct
        // an invalid signature from a valid `Message` and `SecretKey`
        let  data : [u8;8] = transform_u64_to_array_of_u8(*i);
        assert_eq!(ffi::secp256k1_ecdsa_sign(context, &mut ret, msg.as_ptr(),
                                             sk.as_ptr(), ffi::secp256k1_nonce_function_default,
                                             data.as_ptr() as *const c_void), 1);

    }
    Ok(Signature::from(ret))
}


fn transform_u64_to_array_of_u8(x:u64) -> [u8;8] {
    let b1 : u8 = ((x >> 56) & 0xff) as u8;
    let b2 : u8 = ((x >> 48) & 0xff) as u8;
    let b3 : u8 = ((x >> 40) & 0xff) as u8;
    let b4 : u8 = ((x >> 32) & 0xff) as u8;
    let b5 : u8 = ((x >> 24) & 0xff) as u8;
    let b6 : u8 = ((x >> 16) & 0xff) as u8;
    let b7 : u8 = ((x >> 8) & 0xff) as u8;
    let b8 : u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4, b5, b6, b7, b8]
}



impl FromHex for str {
    /// Convert any hexadecimal encoded string (literal, `@`, `&`, or `~`)
    /// to the byte values it encodes.
    ///
    /// You can use the `String::from_utf8` function to turn a
    /// `Vec<u8>` into a string with characters corresponding to those values.
    ///
    /// # Example
    ///
    /// This converts a string literal to hexadecimal and back.
    ///
    /// ```rust
    /// extern crate rustc_serialize;
    /// use rustc_serialize::hex::{FromHex, ToHex};
    ///
    /// fn main () {
    ///     let hello_str = "Hello, World".as_bytes().to_hex();
    ///     println!("{}", hello_str);
    ///     let bytes = hello_str.from_hex().unwrap();
    ///     println!("{:?}", bytes);
    ///     let result_str = String::from_utf8(bytes).unwrap();
    ///     println!("{}", result_str);
    /// }
    /// ```
    fn from_hex(&self) -> Result<Vec<u8>,()> {
        // This may be an overestimate if there is any whitespace
        let mut b = Vec::with_capacity(self.len() / 2);
        let mut modulus = 0;
        let mut buf = 0;

        for (idx, byte) in self.bytes().enumerate() {
            buf <<= 4;

            match byte {
                b'A'...b'F' => buf |= byte - b'A' + 10,
                b'a'...b'f' => buf |= byte - b'a' + 10,
                b'0'...b'9' => buf |= byte - b'0',
                b' ' | b'\r' | b'\n' | b'\t' => {
                    buf >>= 4;
                    continue;
                }
                _ => {
                    let _ = self[idx..].chars().next().unwrap();
                    return Err(());
                }
            }

            modulus += 1;
            if modulus == 2 {
                modulus = 0;
                b.push(buf);
            }
        }

        match modulus {
            0 => Ok(b.into_iter().collect()),
            _ => Err(()),
        }
    }
}

/// A trait for converting hexadecimal encoded values
pub trait FromHex {
    /// Converts the value of `self`, interpreted as hexadecimal encoded data,
    /// into an owned vector of bytes, returning the vector.
    fn from_hex(&self) -> Result<Vec<u8>, ()>;
}
