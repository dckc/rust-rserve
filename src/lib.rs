#![crate_name = "rserve"]
#![crate_type = "lib"]

#![feature(phase)]
#[phase(plugin, link)] extern crate log;
//extern crate debug;

use std::io::net::ip::Port;

pub mod qap;
pub mod rsrv;

pub static DEFAULT_PORT: Port = 6311;

#[deriving(FromPrimitive, Show, Eq, PartialEq)]
#[repr(u32)]
#[allow(non_camel_case_types)]
enum CMD {
// TODO: we're only interested in OCap for now
//        login       = 0x001,
//        voidEval    = 0x002,
//        eval        = 0x003,
//        shutdown    = 0x004,
    CMD_OCcall        = 0x00f,
    CMD_OCinit        = 0x434f7352 // "RsOC"
}
