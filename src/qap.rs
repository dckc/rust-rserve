use std::io::{IoResult};
use std::num::from_uint;
use std::io::MemReader;
use std::rc::Rc;
use std::str::from_utf8;

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


#[deriving(Show, PartialEq, Eq)]
pub enum SExpCell {
    Symbol(String),
    ArrayString(Vec<String>),
    List(Vec<ListItem>),
    SExpWithAttrib(SExp, SExp)
}
#[deriving(Show, PartialEq, Eq)]
pub enum ListItem {
    Car(SExp),
    Tagged(SExp, SExp)
}

pub type SExp = Option<Rc<SExpCell>>; // None = NULL / nil

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

/* XpressionTypes
   REXP - R expressions are packed in the same way as command parameters
   transport format of the encoded Xpressions:
   [0] int type/len (1 byte type, 3 bytes len - same as SET_PAR)
   [4] REXP attr (if bit 8 in type is set)
   [4/8] data .. */
#[deriving(FromPrimitive, Show, Eq, PartialEq)]
#[repr(uint)]
#[allow(non_camel_case_types)]
enum XpressionTypes {
    XT_NULL          = 0,  /* P  data: [0] */
    XT_INT           = 1,  /* -  data: [4]int */
    XT_DOUBLE        = 2,  /* -  data: [8]double */
    XT_STR           = 3,  /* P  data: [n]char null-term. strg. */
    XT_LANG          = 4,  /* -  data: same as XT_LIST */
    XT_SYM           = 5,  /* -  data: [n]char symbol name */
    XT_BOOL          = 6,  /* -  data: [1]byte boolean
							     (1=TRUE, 0=FALSE, 2=NA) */
    XT_S4            = 7,  /* P  data: [0] */

    XT_VECTOR        = 16, /* P  data: [?]REXP,REXP,.. */
    XT_LIST          = 17, /* -  X head, X vals, X tag (since 0.1-5) */
    XT_CLOS          = 18, /* P  X formals, X body  (closure; since 0.1-5) */
    XT_SYMNAME       = 19, /* s  same as XT_STR (since 0.5) */
    XT_LIST_NOTAG    = 20, /* s  same as XT_VECTOR (since 0.5) */
    XT_LIST_TAG      = 21, /* P  X tag, X val, Y tag, Y val, ... (since 0.5) */
    XT_LANG_NOTAG    = 22, /* s  same as XT_LIST_NOTAG (since 0.5) */
    XT_LANG_TAG      = 23, /* s  same as XT_LIST_TAG (since 0.5) */
    XT_VECTOR_EXP    = 26, /* s  same as XT_VECTOR (since 0.5) */
    XT_VECTOR_STR    = 27, /* -  same as XT_VECTOR (since 0.5 but unused, use XT_ARRAY_STR instead) */

    XT_ARRAY_INT     = 32, /* P  data: [n*4]int,int,.. */
    XT_ARRAY_DOUBLE  = 33, /* P  data: [n*8]double,double,.. */
    XT_ARRAY_STR     = 34, /* P  data: string,string,.. (string=byte,byte,...,0) padded with '\01' */
    XT_ARRAY_BOOL_UA = 35, /* -  data: [n]byte,byte,..  (unaligned! NOT supported anymore) */
    XT_ARRAY_BOOL    = 36, /* P  data: int(n),byte,byte,... */
    XT_RAW           = 37, /* P  data: int(n),byte,byte,... */
    XT_ARRAY_CPLX    = 38, /* P  data: [n*16]double,double,... (Re,Im,Re,Im,...) */

    XT_UNKNOWN       = 48, /*  deprecated/removed.
                             if a client doesn't need to support old Rserve versions,
                             those can be safely skipped.
  Total primary: 4 trivial types (NULL, STR, S4, UNKNOWN) + 6 array types + 3 recursive types
*/
}

impl XpressionTypes {
    fn decode(word: u32) -> IoResult<(XpressionTypes, bool, u32)> {
        let (has_attr, ty, len) = (word & XT_HAS_ATTR > 0,  word & 0x3F, word >> 8);

        match from_uint::<XpressionTypes>(ty as uint) {
            None => invalid_input("bad XT", format!("{}", ty)),
            Some(xt) => Ok((xt, has_attr, len))
        }
    }
}


/* new in 0102: if this flag is set then the length of the object
is coded as 56-bit integer enlarging the header by 4 bytes */
// TODO: static XT_LARGE: u32 = 64;
/* flag; if set, the following REXP is the
attribute */
static XT_HAS_ATTR: u32 = 128;

/* the use of attributes and vectors results in recursive storage of REXPs */


//ack: http://hackage.haskell.org/package/rclient-0.1.0.0/docs/Network-Rserve-Client.html
pub trait QAP1Decode {
    fn read_message(&mut self, hd: Option<(u32, u32, u32, u32)>) -> IoResult<Message>;
    fn read_header(&mut self) -> IoResult<(u32, u32, u32, u32)>;
}

pub trait DataDecode {
    fn read_datum(&mut self) -> IoResult<Datum>;
    fn read_sexp(&mut self) -> IoResult<SExp>;
}

impl<R: Reader> QAP1Decode for R {
    fn read_message(&mut self, hd: Option<(u32, u32, u32, u32)>) -> IoResult<Message> {
        let (cmd, len, msg_id, lenhi) = match hd {
            Some(hd) => hd,
            None => try!(self.read_header())
        };
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
}

impl<R: Reader + Seek> DataDecode for R {
    fn read_datum(&mut self) -> IoResult<Datum> {
        let word = try!(self.read_le_u32());
        let (ty, len) = (word as u8, word >> 8);
        debug!("read_datum got ty={:u}, len=0x{:x}", ty, len);

        match from_uint::<DT>(ty as uint) {
            None => invalid_input("bad DT", format!("DT: 0x{:x}", ty)),
            Some(dt) => match dt {
                DT_INT => self.read_le_i32().map(|i| DTInt(i)),
                // TODO... 
                DT_SEXP => self.read_sexp().map(|e| DTSExp(e))
            }
        }
    }

    fn read_sexp(&mut self) -> IoResult<SExp> {
        let (ty, has_attr, mut len) = try!(XpressionTypes::decode(try!(self.read_le_u32())));

        let attr = match has_attr {
            true => {
                let here = try!(self.tell());
                let a = Some(try!(self.read_sexp()));
                len -= (try!(self.tell()) - here) as u32;
                a
            },
            false => None
        };

        let x = match ty {
            XT_NULL => None,
            XT_SYMNAME => to_symbol(try!(self.read_exact(len as uint))),
            XT_ARRAY_STR => to_array_str(try!(self.read_exact(len as uint))),
            XT_LIST_TAG => {
                let mut items = Vec::new();
                while (try!(self.tell()) as u32) < len {
                    let (val, tag) = (try!(self.read_sexp()), try!(self.read_sexp()));
                    items.push(Tagged(val, tag));
                    debug!("another list item? tell={} len={}", try!(self.tell()) as u32, len);
                }
                Some(Rc::new(List(items)))
            },
            _ => fail!("@@TODO: read_sexp: ty {}, has_attr {}, len: 0x{:x}", has_attr, ty, len)
        };

        debug!("read_sexp: attr={} x ={}", attr, x);
        match attr {
            Some(attr) => Ok(Some(Rc::new(SExpWithAttrib(attr, x)))),
            None => Ok(x)
        }
    }
}


fn to_symbol(bytes: Vec<u8>) -> SExp {
    let bytes = match bytes.iter().position(|b| *b == 0) {
        Some(i) => bytes.slice_to(i),
        None => bytes.as_slice()
    };
    let name = to_string(bytes);
    debug!("SYMNAME name: {}", name);
    Some(Rc::new(Symbol(name)))
}


fn to_array_str(bytes: Vec<u8>) -> SExp {
    let mut items = Vec::new();
    let mut skip_pad = false;
    for section in bytes.as_slice().split(|b| *b == 0) {
        if !skip_pad {
            items.push(to_string(section))
        }
        debug!("XT_ARRAY_STR: items={}", items);
        skip_pad = if skip_pad { false } else { (section.len() + 1) % 4 != 0 }
    }
    Some(Rc::new(ArrayString(items)))
}

fn to_string(bytes: &[u8]) -> String {
    match from_utf8(bytes) {
        Some(s) => s.to_string(),
        // Use Show instance of &[u8]
        None => bytes.to_string()
    }
}


#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::{to_array_str, ArrayString};

    #[test]
    fn str_pad() {
        assert_eq!(to_array_str("abc\0defg\0\x01\x01\x01".as_bytes().to_vec()),
                   Some(Rc::new(ArrayString(vec!("abc".to_string(),
                                                 "defg".to_string())))))
        assert_eq!(to_array_str("class\0\x01\x01".as_bytes().to_vec()),
                   Some(Rc::new(ArrayString(vec!("class".to_string())))))
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
