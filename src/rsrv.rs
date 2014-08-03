use std::str::from_utf8;
use std::io::{IoError, IoResult, InvalidInput};
use std::iter::range_inclusive;

bitflags!(
    flags Flags: u32 {
        static CMD_RESP    = 0x10000,
        static RESP_OK     = 0x0001,
        static RESP_ERR    = 0x0002,
        static CMD_OOB     = 0x20000
    }
)

#[deriving(Show, PartialEq, Eq)]
pub enum ServerProtocol {
    QAP1(String, Vec<ServerAttribute>) // exactly 5. hm.
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
    AnyAttr(Result<String, (u8, u8, u8, u8)>)
}

impl ServerAttribute {
    pub fn new(bytes: &[u8]) -> ServerAttribute {
        assert!(bytes.len() == 4);
        let ch = |i| bytes[i] as char;
        let other = || AnyAttr({
            match from_utf8(bytes) {
                Some(txt) => Ok(txt.to_string()),
                None => Err((bytes[0], bytes[1], bytes[2], bytes[3]))
            }
        });

        match (ch(0), ch(1)) {
            ('R', _) => match (ch(1).to_digit(10),
                               ch(2).to_digit(10),
                               ch(3).to_digit(10)) {
                (Some(d1), Some(d2), Some(d3)) => RVersion(d1 as u8, d2 as u8, d3 as u8),
                _ => other()
            },
            ('A', 'R') => AuthorizationRequired(match (ch(2), ch(3)) {
                ('p', 't') => PlainText,
                ('u', 'c') => UnixCrypt,
                ('m', '5') => MD5,
                (_, _) => AnyAuth(ch(2), ch(3))
            }),
            ('K', _) => Key(bytes[1], bytes[2], bytes[3]),
            (_, _) => other()
        }
    }
}

#[deriving(Show, PartialEq, Eq)]
pub enum AuthType {
    PlainText,
    UnixCrypt,
    MD5,
    AnyAuth(char, char)
}


impl ServerProtocol {
    pub fn decode_id_string(buf: &[u8]) -> IoResult<ServerProtocol> {
        if buf.len() != 32 {
            return Err(IoError{ kind: InvalidInput, desc: "id string length must be 32", detail: None});
        }

        #[inline]
        fn chunk<'b>(buf: &'b [u8], i: uint) -> &'b [u8] { buf.slice(i * 4, i * 4 + 4) }
        let check = |attr: AttrIndex, expected: &str| {
            let actual = chunk(buf, attr as uint);
            if actual == expected.as_bytes() { Ok(()) }
            else { Err(IoError{ kind: InvalidInput, desc: "unsupported attribute",
                                detail: Some(format!("expected {} for {} but got {}",
                                                     expected, attr, ServerAttribute::new(actual))) }) }
        };
        try!(check(IDsig, "Rsrv"));
        let version = ServerAttribute::new(chunk(buf, ServerVersion as uint));
        try!(check(Protocol, "QAP1"));

        let attrs = range_inclusive(Opt4 as uint, Opt8 as uint).map(
            |ix| ServerAttribute::new(chunk(buf, ix))).collect();
        match version {
            AnyAttr(Ok(txt)) => Ok(QAP1(txt.to_string(), attrs)),
            _ => Err(IoError{ kind: InvalidInput, desc: "bad version",
                              detail: Some(format!("attr: {}", version)) })
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
        ServerProtocol::decode_id_string(buf)
    }
}


#[cfg(test)]
mod tests {
    use super::{ServerProtocol, QAP1,
                RVersion, AuthorizationRequired, Key, AnyAttr,
                MD5};

    #[test]
    fn empty_id_string() {
        match ServerProtocol::decode_id_string("".as_bytes()) {
            Ok(_) => fail!(),
            Err(e) => debug!("{}", e)
        }
    }

    #[test]
    fn ok_id_string() {
        let actual = ServerProtocol::decode_id_string("Rsrv0103QAP1****R151ARm5Kabc4444".as_bytes());
        debug!("protcol: {}", actual);

        assert_eq!(actual,
                   Ok(QAP1("0103".to_string(),
                           vec!(AnyAttr(Ok("****".to_string())),
                                RVersion(1, 5, 1),
                                AuthorizationRequired(MD5),
                                Key('a' as u8, 'b' as u8, 'c' as u8),
                                AnyAttr(Ok("4444".to_string()))))))
    }

    #[test]
    fn unknown_id_string() {
        match ServerProtocol::decode_id_string("Rsrv0100QAP2****R151ARm5Kabc4444".as_bytes()) {
            Ok(_) => fail!(),
            Err(e) => debug!("{}", e)
        }
    }

    #[test]
    fn decode_sever_caps() {
    }
}
