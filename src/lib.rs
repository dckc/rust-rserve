#![crate_name = "rserve"]
#![crate_type = "lib"]

#![feature(phase)]
#[phase(plugin, link)] extern crate log;
extern crate debug; // @@

use std::io::net::ip::Port;
use std::io::{IoResult, IoError, InvalidInput};

pub mod sexp;
pub mod qap;
pub mod rsrv;
pub mod oc;

pub static DEFAULT_PORT: Port = 6311;

//TODO use this througout
#[inline]
pub fn invalid_input<T>(desc: &'static str, detail: String) -> IoResult<T> {
    Err(IoError{ kind: InvalidInput, desc: desc, detail: Some(detail) })
}
