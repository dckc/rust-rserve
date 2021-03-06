use std::str::from_utf8;
use std::io::{IoError, IoResult, InvalidInput};
use std::io::net::ip::Port;
use std::iter::range_inclusive;
use std::io::TcpStream;

bitflags!(
    flags Flags: u32 {
        const CMD_RESP    = 0x10000,
        const RESP_OK     = 0x0001,
        const RESP_ERR    = 0x0002,
        const CMD_OOB     = 0x20000
    }
);

#[deriving(Show, PartialEq, Eq)]
pub enum ServerProtocol {
    QAP1(String, Vec<ServerAttribute>) // exactly 5. hm.
}

#[deriving(FromPrimitive, Show, PartialEq, Eq, Copy)]
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
        use self::ServerAttribute::{
            AnyAttr,
            AuthorizationRequired,
            Key,
            RVersion,
        };
        use self::AuthType:: {
            AnyAuth,
            MD5,
            PlainText,
            UnixCrypt,
        };

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

#[deriving(Show, PartialEq, Eq, Copy)]
pub enum AuthType {
    PlainText,
    UnixCrypt,
    MD5,
    AnyAuth(char, char)
}


impl ServerProtocol {
    pub fn decode_id_string(buf: &[u8]) -> IoResult<ServerProtocol> {
        use self::AttrIndex::{IDsig, ServerVersion, Protocol, Opt4, Opt8};
        use self::ServerAttribute::{AnyAttr};
        use self::ServerProtocol::QAP1;

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
        try!(self.read_at_least(32, buf.as_mut_slice()));
        ServerProtocol::decode_id_string(buf.as_slice())
    }
}

pub fn connect(host: &str, port: Option<Port>) -> IoResult<(TcpStream, ServerProtocol)> {
    let mut socket = try!(TcpStream::connect((host, port.unwrap_or(super::DEFAULT_PORT))));
    let protocol = try!(socket.read_id_string());
    Ok((socket, protocol))
}


#[cfg(test)]
mod tests {
    use super::ServerProtocol;
    use super::ServerProtocol::QAP1;
    use super::ServerAttribute::{
        AnyAttr, RVersion, AuthorizationRequired, Key};
    use super::AuthType::MD5;

    #[test]
    fn empty_id_string() {
        match ServerProtocol::decode_id_string("".as_bytes()) {
            Ok(_) => panic!(),
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
            Ok(_) => panic!(),
            Err(e) => debug!("{}", e)
        }
    }

    #[test]
    fn decode_sever_caps() {
    }
}
