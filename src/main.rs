extern crate rserve;

use rserve::oc;

pub fn main() {
   let (mut socket, caps) = oc::connect("127.0.0.1", None).unwrap();
    println!("caps: {}", caps);
}

