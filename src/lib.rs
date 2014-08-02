#![feature(phase)]
#[phase(plugin, link)] extern crate log;
//extern crate debug;

use std::io::net::ip::Port;
use std::io::{IoResult, IoError, InvalidInput};
use std::iter::range_inclusive;


pub static DEFAULT_PORT: Port = 6311;

#[deriving(Show, PartialEq, Eq)]
pub enum ServerProtocol {
    QAP1(Vec<ServerAttribute>) // exactly 5. hm.
}

#[deriving(FromPrimitive, Show, PartialEq, Eq)]
#[repr(uint)]
pub enum AttrIndex {
    IDsig = 0, ServerVersion, Protocol, Opt4,
    Opt5, Opt6, Opt7, Opt8
}

#[deriving(Show, PartialEq, Eq)]
pub enum ServerAttribute {
    // TODO: consider keeping the Ascii constraint in the type
    RVersion(char, char, char),
    AuthorizationRequired(AuthType),
    Key(char, char, char),
    Other(char, char, char, char)
}

#[deriving(Show, PartialEq, Eq)]
pub enum AuthType {
    PlainText,
    UnixCrypt,
    MD5
}

pub fn decode_id_string(buf: &[u8]) -> IoResult<ServerProtocol> {
    if buf.len() != 32 {
        return Err(IoError{ kind: InvalidInput, desc: "id string length must be 32", detail: None});
    }

    match buf.to_ascii_opt() {
        None => Err(IoError{ kind: InvalidInput, desc: "must be ascii", detail: None}),
        Some(chars) => {
            // TODO: figure out how to use a pattern here rather than val0, val1
            for attr_val in [(IDsig, "Rsrv"),
                             (ServerVersion, "0100"),
                             (Protocol, "QAP1")].iter() {
                let attr = (*attr_val).val0();
                let expected = (*attr_val).val1();
                let offset = attr as uint * 4;
                let actual = chars.slice(offset, offset + 4);
                if actual != expected.to_ascii() {
                    return Err(IoError{ kind: InvalidInput, desc: "unsupported attribute",
                                        detail: Some(format!("expected {} for {} but got {}",
                                                             expected, attr, actual)) })
                }
            }
            let attrs = range_inclusive(Opt4 as uint, Opt8 as uint).map(|ix| {
                let offset = ix * 4;
                match (chars[offset].to_char(),
                       chars[offset + 1].to_char(),
                       chars[offset + 2].to_char(),
                       chars[offset + 3].to_char())  {
                    ('R', c2, c3, c4) => RVersion(c2, c3, c4),
                    ('A', 'R', 'p', 't') => AuthorizationRequired(PlainText),
                    ('A', 'R', 'u', 'c') => AuthorizationRequired(UnixCrypt),
                    ('A', 'R', 'm', '5') => AuthorizationRequired(MD5),
                    ('K', c2, c3, c4) => Key(c2, c3, c4),
                    (c1, c2, c3, c4) => Other(c1, c2, c3, c4)
                }
            }).collect();
            Ok(QAP1(attrs))
        }
    }
}

pub trait ReadIDString {
    fn read_id_string(&mut self) -> IoResult<ServerProtocol>;
}

impl<R: Reader> ReadIDString for R {
    fn read_id_string(&mut self) -> IoResult<ServerProtocol> {
        let mut buf = [0u8, ..32];
        try!(self.read_at_least(32, buf));
        decode_id_string(buf)
    }
}


#[cfg(test)]
mod tests {
    use super::{decode_id_string, QAP1,
                RVersion, AuthorizationRequired, Key, Other,
                MD5};

    #[test]
    fn empty_id_string() {
        match decode_id_string("".as_bytes()) {
            Ok(_) => fail!(),
            Err(e) => debug!("{}", e)
        }
    }

    #[test]
    fn ok_id_string() {
        assert_eq!(decode_id_string("Rsrv0100QAP1****R151ARm5Kabc4444".as_bytes()),
                   Ok(QAP1(vec!(Other('*', '*', '*', '*'),
                                RVersion('1', '5', '1'),
                                AuthorizationRequired(MD5),
                                Key('a', 'b', 'c'),
                                Other('4', '4', '4', '4')))))
    }

    #[test]
    fn unknown_id_string() {
        match decode_id_string("Rsrv0100QAP2****R151ARm5Kabc4444".as_bytes()) {
            Ok(_) => fail!(),
            Err(e) => debug!("{}", e)
        }
    }

    #[test]
    fn decode_sever_caps() {
    }
}
