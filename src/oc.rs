use std::io::net::ip::Port;
use std::io::net::tcp::TcpStream;
use std::io::{IoResult};
use std::num::from_uint;

use super::DEFAULT_PORT;
use super::qap::{QAP1Decode, DTSExp, SExp};
use super::invalid_input;

#[deriving(FromPrimitive, Show, Eq, PartialEq)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum CommandInit {
    Rsrv              = 0x76727352, // "Rsrv"
    CMD_OCinit        = 0x434f7352  // "RsOC"
}

pub fn connect(host: &str, port: Option<Port>) -> IoResult<(TcpStream, SExp)> {
    let mut socket = try!(TcpStream::connect(host, port.unwrap_or(DEFAULT_PORT)));
    debug!("connected: {:?}", socket);

    let (cmd, len, msg_id, lenhi) = try!(socket.read_header());
    debug!("header: {}", (cmd, len, msg_id, lenhi));

    match from_uint::<CommandInit>(cmd as uint) {
        Some(CMD_OCinit) => {
            debug!("got CMD_OCinit");
            let init = try!(socket.read_message(Some((cmd, len, msg_id, lenhi))));
            match init.content {
                Some(DTSExp(e)) => Ok((socket, e)),
                _ => invalid_input("bad CMD_OCinit", format!("content: {}", init.content))
            }
        }
        _ => invalid_input("expected RsOC", format!("cmd: {}", cmd))
    }
}
