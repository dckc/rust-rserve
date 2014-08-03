use std::io::{IoResult, IoError, InvalidInput};
use std::num::from_uint;

use super::{CMD};


#[deriving(PartialEq, Eq, Show)]
pub struct QAP1Header {
    cmd: CMD,
    len: u32,
    msg_id: u32,
    lenhi: u32 // TODO: combine len, lenhi into an enum
}

pub trait QAP1Decode {
    fn read_header(&mut self) -> IoResult<(QAP1Header)>;
}

impl<R: Reader> QAP1Decode for R {
    fn read_header(&mut self) -> IoResult<(QAP1Header)> {
        // TODO: read all 16 bytes and then parse it
        let cmd = try!(self.read_le_u32());
        let len = try!(self.read_le_u32());
        let msg_id = try!(self.read_le_u32());
        let lenhi = try!(self.read_le_u32());
        match from_uint::<CMD>(cmd as uint) {
            Some(cmd) => Ok(QAP1Header{ cmd: cmd, len: len, msg_id: msg_id, lenhi: lenhi }),
            None => Err(IoError{ kind: InvalidInput, desc: "bad/unsupported CMD",
                                 detail: Some(format!("command: {}", cmd)) } )
        }
    }
    
}

trait QAP1Encode {
    fn write_header(&mut self, h: QAP1Header) -> IoResult<()>;
}

impl<W: Writer> QAP1Encode for W {
    fn write_header(&mut self, h: QAP1Header) -> IoResult<()> {
        try!(self.write_le_u32(h.cmd as u32));
        try!(self.write_le_u32(h.len));
        try!(self.write_le_u32(h.msg_id));
        try!(self.write_le_u32(h.lenhi));
        Ok(())
    }
}
