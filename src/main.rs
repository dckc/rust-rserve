extern crate rserve;

use rserve::qap::QAP1Decode;

pub fn main() {
    let mut socket = std::io::TcpStream::connect("127.0.0.1", rserve::DEFAULT_PORT).unwrap();
    let msg = socket.read_message(None);
    println!("message: {}", msg)
/*
   let (mut socket, caps) = rserve::oc::connect("127.0.0.1", None).unwrap();
    println!("caps: {}", caps);
*/
}

