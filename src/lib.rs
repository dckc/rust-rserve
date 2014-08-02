#![crate_name = "rserve"]
#![crate_type = "lib"]

#![feature(phase)]
#[phase(plugin, link)] extern crate log;
//extern crate debug;

use std::io::net::ip::Port;
use std::io::{IoResult, IoError, InvalidInput};
use std::iter::range_inclusive;
use std::str::from_utf8;

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
    RVersion(u8, u8, u8),
    AuthorizationRequired(AuthType),
    Key(u8, u8, u8),
    AnyAttr(u8, u8, u8, u8)
}

#[deriving(Show, PartialEq, Eq)]
pub enum AuthType {
    PlainText,
    UnixCrypt,
    MD5,
    AnyAuth(u8, u8)
}

pub fn decode_id_string(buf: &[u8]) -> IoResult<ServerProtocol> {
    debug!("decode_id_string(buf={})", buf);

    if buf.len() != 32 {
        return Err(IoError{ kind: InvalidInput, desc: "id string length must be 32", detail: None});
    }


    let required = [(IDsig, "Rsrv"),
                    (ServerVersion, "0103"),  // hmm... accept other minor versions?
                    (Protocol, "QAP1")];
    let check = |attr: AttrIndex, expected| {
        let offset = attr as uint * 4;
        let actual = buf.slice(offset, offset + 4);
        match from_utf8(actual) {
            Some(txt) if txt == expected => Ok(()),
            Some(txt) => Err(IoError{ kind: InvalidInput, desc: "unsupported attribute",
                                      detail: Some(format!("expected {} for {} but got {}",
                                                           expected, attr, txt)) }),
            None => Err(IoError{ kind: InvalidInput, desc: "cannot decode attribute as utf-8",
                                 detail: Some(format!("bytes: {}", actual)) })
        }
    };
    for attr_val in required.iter() {
        // TODO: figure out how to use a pattern here rather than val0, val1
        let attr = (*attr_val).val0();
        let expected = (*attr_val).val1();
        match check(attr, expected) {
            Ok(_) => (),
            Err(e) => return Err(e)
        }
    }

    let attrs = range_inclusive(Opt4 as uint, Opt8 as uint).map(|ix| {
        let offset = ix * 4;
        let (b0, b1, b2, b3) = (buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
        match (b0 as char, b1 as char) {
            ('R', _) => RVersion(b1, b2, b3),
            ('A', 'R') => AuthorizationRequired(match (b2 as char, b3 as char) {
                ('p', 't') => PlainText,
                ('u', 'c') => UnixCrypt,
                ('m', '5') => MD5,
                (_, _) => AnyAuth(b2, b3)
            }),
            ('K', _) => Key(b1, b2, b3),
            (_, _) => AnyAttr(b0, b1, b2, b3)
        }
    }).collect();
    Ok(QAP1(attrs))
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
                RVersion, AuthorizationRequired, Key, AnyAttr,
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
        let actual = decode_id_string("Rsrv0103QAP1****R151ARm5Kabc4444".as_bytes());
        debug!("protcol: {}", actual);
        assert_eq!(actual,
                   Ok(QAP1(vec!(AnyAttr('*' as u8, '*' as u8, '*' as u8, '*' as u8),
                                RVersion('1' as u8, '5' as u8, '1' as u8),
                                AuthorizationRequired(MD5),
                                Key('a' as u8, 'b' as u8, 'c' as u8),
                                AnyAttr('4' as u8, '4' as u8, '4' as u8, '4' as u8)))))
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
