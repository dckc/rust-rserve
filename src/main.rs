extern crate rserve;

use std::io::TcpStream;

use rserve::{ReadIDString};

pub fn main() {
    let mut socket = TcpStream::connect("127.0.0.1", rserve::DEFAULT_PORT).unwrap();
    let protocol = socket.read_id_string().unwrap();
    println!("protocol: {}", protocol);
}

