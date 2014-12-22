extern crate rserve;

use rserve::oc;

pub fn main() {
   let (_, caps) = oc::connect("127.0.0.1", None).unwrap();
    println!("caps: {}", caps);
}

