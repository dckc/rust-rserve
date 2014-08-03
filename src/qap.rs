use std::io::{IoResult};
use std::num::from_uint;
use std::io::MemReader;

use super::sexp::SExp;
use super::invalid_input;

#[deriving(PartialEq, Eq, Show)]
pub struct Message {
    pub cmd: u32,
    pub msg_id: u32,
    pub content: Option<Datum>
}

#[deriving(PartialEq, Eq, Show)]
pub enum Datum {
    DTInt(i32),
    //TODO
    //...
    DTSExp(SExp)
}


/* data types for the transport protocol (QAP1)
   do NOT confuse with XT_.. values. */

#[deriving(PartialEq, Eq, Show, FromPrimitive)]
#[repr(uint)]
#[allow(non_camel_case_types)]
enum DT{
    DT_INT    =    1  ,
/* @@ TODO
    // int
    // char
    DT_CHAR   =    2  ,
    // double
    DT_DOUBLE =    3  ,
    // 0 terminted string
    DT_STRING =    4  ,
    // stream of bytes (unlike DT_STRING may contain 0)
    DT_BYTESTREAM = 5  ,
*/
    //encoded S
    DT_SEXP   =    10 ,

/* TODO
    // array of objects (i.e. first 4 bytes specify how many
    //                   subsequent objects are part of the array; 0 is legitimate)
    DT_ARRAY  =    11 ,
    // custom types not defined in the protocol but used
    // by applications
    DT_CUSTOM =    32 ,
    // new in 0102: if this flag is set then the length of the object
    // is coded as 56-bit integer enlarging the header by 4 bytes
    //TODO DT_LARGE  =    64
*/
}


//ack: http://hackage.haskell.org/package/rclient-0.1.0.0/docs/Network-Rserve-Client.html
pub trait QAP1Decode {
    fn read_message(&mut self, hd: Option<(u32, u32, u32, u32)>) -> IoResult<Message>;
    fn read_header(&mut self) -> IoResult<(u32, u32, u32, u32)>;
    fn read_datum(&mut self) -> IoResult<Datum>;
    fn read_sexp(&mut self, len: u32) -> IoResult<SExp>;
}

impl<R: Reader> QAP1Decode for R {
    fn read_message(&mut self, hd: Option<(u32, u32, u32, u32)>) -> IoResult<Message> {
        let (cmd, len, msg_id, lenhi) = hd.unwrap_or(try!(self.read_header()));
        assert!(lenhi == 0); // TODO: support long mode

        debug!("reading {} bytes of data...", len);
        let data = try!(self.read_exact(len as uint));
        debug!("got data");
        let content = match data.len() > 0 {
            true => Some(try!(MemReader::new(data).read_datum())),
            false => None
        };

        Ok(Message { cmd: cmd, msg_id: msg_id, content: content  })
    }
    
    fn read_header(&mut self) -> IoResult<(u32, u32, u32, u32)> {
        let mut hd = MemReader::new(try!(self.read_exact(4 * 4)));

        let cmd = try!(hd.read_le_u32());
        let len = try!(hd.read_le_u32());
        let msg_id = try!(hd.read_le_u32());
        let lenhi = try!(hd.read_le_u32());
        Ok((cmd, len, msg_id, lenhi))
    }

    fn read_datum(&mut self) -> IoResult<Datum> {
        let word = try!(self.read_le_u32());
        let (ty, len) = (word as u8, word >> 8);
        debug!("read_datum got ty={:u}, len=0x{:x}", ty, len);

        match from_uint::<DT>(ty as uint) {
            None => invalid_input("bad DT", format!("DT: 0x{:x}", ty)),
            Some(dt) => match dt {
                DT_INT => self.read_le_i32().map(|i| DTInt(i)),
                // TODO... 
                DT_SEXP => self.read_sexp(len).map(|e| DTSExp(e))
            }
        }
    }

    fn read_sexp(&mut self, len: u32) -> IoResult<SExp> {
        let word = try!(self.read_le_u32());
        let (ty, len) = (word as u8, word >> 8);
        fail!("@@TODO: read_sexp: ty 0x{:x}, len: 0x{:x}", ty, len)
    }
}

/*TODO
trait QAP1Encode {
    fn write_message(&mut self, h: QAP1Header) -> IoResult<()>;
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
*/
