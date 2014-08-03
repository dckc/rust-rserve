extern crate rserve;

use std::io::TcpStream;

use rserve::qap::{QAP1Decode};

pub fn main() {
    let mut socket = TcpStream::connect("127.0.0.1", rserve::DEFAULT_PORT).unwrap();
    // This is not for RsOC protocol
    // let protocol = socket.read_id_string().unwrap();
    // println!("protocol: {}", protocol);

    let caps_hd = socket.read_header().unwrap();
    println!("header: {}", caps_hd);
}

