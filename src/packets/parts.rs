use std::net::Ipv4Addr;

#[derive(Debug, PartialEq)]
pub struct Question {
    pub qname: String,
    pub qtype: QueryType,
    pub qclass: u16,
}

impl Question {
    pub fn new(qname: String, qtype: QueryType, qclass: u16) -> Question {
        Question {
            qname,
            qtype,
            qclass,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.qname.split('.') {
            bytes.push(part.len() as u8);
            for byte in part.bytes() {
                bytes.push(byte);
            }
        }
        bytes.push(0);
        bytes.append(&mut self.qtype.to_bytes());
        bytes.push((self.qclass >> 8) as u8);
        bytes.push((self.qclass & 0xff) as u8);
        bytes
    }
}

#[derive(Debug, PartialEq)]
pub struct Flags {
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
}

impl Flags {
    pub fn new(bytes: [u8; 2]) -> Flags {
        let byte1 = bytes[0];
        let byte2 = bytes[1];

        Flags {
            qr: (byte1 & 0b1000_0000) != 0,
            opcode: (byte1 & 0b0111_1000) >> 3,
            aa: (byte1 & 0b0000_0100) != 0,
            tc: (byte1 & 0b0000_0010) != 0,
            rd: (byte1 & 0b0000_0001) != 0,
            ra: (byte2 & 0b1000_0000) != 0,
            z: (byte2 & 0b0111_0000) >> 4,
            rcode: byte2 & 0b0000_1111,
        }
    }

    pub fn to_bytes(&self) -> [u8; 2] {
        let mut bytes = [0; 2];
        bytes[0] |= if self.qr { 0b1000_0000 } else { 0 };
        bytes[0] |= self.opcode << 3;
        bytes[0] |= if self.aa { 0b0000_0100 } else { 0 };
        bytes[0] |= if self.tc { 0b0000_0010 } else { 0 };
        bytes[0] |= if self.rd { 0b0000_0001 } else { 0 };
        bytes[1] |= if self.ra { 0b1000_0000 } else { 0 };
        bytes[1] |= self.z << 4;
        bytes[1] |= self.rcode;
        bytes
    }
}

#[derive(Debug, PartialEq)]
pub struct PacketHeader {
    pub id: u16,
    pub flags: Flags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl PacketHeader {
    pub fn from_raw_header(raw_header: [u8; 12]) -> PacketHeader {
        PacketHeader {
            id: (raw_header[0] as u16) << 8 | raw_header[1] as u16,
            flags: Flags::new([raw_header[2], raw_header[3]]),
            qdcount: (raw_header[4] as u16) << 8 | raw_header[5] as u16,
            ancount: (raw_header[6] as u16) << 8 | raw_header[7] as u16,
            nscount: (raw_header[8] as u16) << 8 | raw_header[9] as u16,
            arcount: (raw_header[10] as u16) << 8 | raw_header[11] as u16,
        }
    }

    pub fn empty() -> PacketHeader {
        PacketHeader {
            id: 0,
            flags: Flags::new([0, 0]),
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push((self.id >> 8) as u8);
        bytes.push((self.id & 0xff) as u8);
        bytes.append(&mut self.flags.to_bytes().to_vec());
        bytes.push((self.qdcount >> 8) as u8);
        bytes.push((self.qdcount & 0xff) as u8);
        bytes.push((self.ancount >> 8) as u8);
        bytes.push((self.ancount & 0xff) as u8);
        bytes.push((self.nscount >> 8) as u8);
        bytes.push((self.nscount & 0xff) as u8);
        bytes.push((self.arcount >> 8) as u8);
        bytes.push((self.arcount & 0xff) as u8);
        bytes
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum QueryType {
    UNKNOWN(u16),
    A,
}

impl QueryType {
    pub fn new(qtype: u16) -> QueryType {
        match qtype {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN(qtype),
        }
    }

    pub fn into(self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::UNKNOWN(qtype) => qtype,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            QueryType::A => vec![0, 1],
            QueryType::UNKNOWN(qtype) => vec![(qtype >> 8) as u8, (qtype & 0xff) as u8],
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Record {
    UNKNOWN {
        domain: String,
        qtype: u16,
        rlen: u16,
        ttl: u32,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
}

impl Record {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Record::UNKNOWN {
                domain,
                qtype,
                rlen,
                ttl,
            } => {
                let mut bytes = Vec::new();
                for part in domain.split('.') {
                    bytes.push(part.len() as u8);
                    for byte in part.bytes() {
                        bytes.push(byte);
                    }
                }
                bytes.push(0);
                bytes.append(&mut vec![(qtype >> 8) as u8, (qtype & 0xff) as u8]);
                bytes.append(&mut vec![(rlen >> 8) as u8, (rlen & 0xff) as u8]);
                bytes.append(&mut ttl.to_be_bytes().to_vec());
                bytes
            }
            Record::A { domain, addr, ttl } => {
                let mut bytes = Vec::new();
                for part in domain.split('.') {
                    bytes.push(part.len() as u8);
                    for byte in part.bytes() {
                        bytes.push(byte);
                    }
                }
                bytes.push(0);
                bytes.append(&mut vec![0, 1]);
                bytes.append(&mut vec![0, 1]);
                bytes.append(&mut ttl.to_be_bytes().to_vec());
                bytes.append(&mut vec![0, 4]);
                bytes.append(&mut addr.octets().to_vec());
                bytes
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_to_bytes() {
        let record = Record::A {
            domain: "www.google.com".to_string(),
            addr: Ipv4Addr::new(8, 8, 8, 8),
            ttl: 3600,
        };
        let bytes = record.to_bytes();
        assert_eq!(
            bytes,
            vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
                0, 1, 0, 1, 0, 0, 14, 16, 0, 4, 8, 8, 8, 8
            ]
        );
    }

    #[test]
    fn header_to_bytes() {
        let header = PacketHeader {
            id: 1,
            flags: Flags::new([0b0000_0000, 0b0000_0000]),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        let bytes = header.to_bytes();
        assert_eq!(bytes, vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn flags_to_bytes() {
        let flags = Flags {
            qr: false,
            opcode: 1,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: 2,
        };
        let bytes = flags.to_bytes();
        assert_eq!(bytes, [0b0000_1001, 0b1000_0010]);
    }

    #[test]
    fn question_to_bytes() {
        let question = Question::new("www.google.com".to_string(), QueryType::A, 1);
        let bytes = question.to_bytes();
        assert_eq!(
            bytes,
            vec![
                3, b'w', b'w', b'w', 6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
                0, 1, 0, 1
            ]
        );
    }

    #[test]
    fn parse_qdcount() {
        let mut raw_header = [0; 12];
        raw_header[4] = 0b0000_0000;
        raw_header[5] = 0b0000_0001;
        let parsed_header = PacketHeader::from_raw_header(raw_header);
        assert_eq!(parsed_header.qdcount, 1);
    }

    #[test]
    fn parse_ancount() {
        let mut raw_header = [0; 12];
        raw_header[6] = 0b0000_0000;
        raw_header[7] = 0b0000_0001;
        let parsed_header = PacketHeader::from_raw_header(raw_header);
        assert_eq!(parsed_header.ancount, 1)
    }

    #[test]
    fn parse_nscount() {
        let mut raw_header = [0; 12];
        raw_header[8] = 0b0000_0000;
        raw_header[9] = 0b0000_0001;
        let parsed_header = PacketHeader::from_raw_header(raw_header);
        assert_eq!(parsed_header.nscount, 1)
    }

    #[test]
    fn parse_arcount() {
        let mut raw_header = [0; 12];
        raw_header[10] = 0b0000_0000;
        raw_header[11] = 0b0000_0001;
        let parsed_header = PacketHeader::from_raw_header(raw_header);
        assert_eq!(parsed_header.arcount, 1)
    }

    #[test]
    fn parse_packet_id() {
        let mut raw_header = [0; 12];
        raw_header[0] = 0b0000_0000;
        raw_header[1] = 0b0000_0001;
        let parsed_header = PacketHeader::from_raw_header(raw_header);
        assert_eq!(parsed_header.id, 1);
    }

    #[test]
    fn flag_qr() {
        let flags = Flags::new([0b1000_0000, 0b0000_0000]);
        assert_eq!(flags.qr, true);
    }

    #[test]
    fn flag_opcode() {
        let flags = Flags::new([0b0001_0000, 0b0000_0000]);
        assert_eq!(flags.opcode, 2);
    }

    #[test]
    fn flag_aa() {
        let flags = Flags::new([0b0000_0100, 0b0000_0000]);
        assert_eq!(flags.aa, true);
    }

    #[test]
    fn flag_tc() {
        let flags = Flags::new([0b0000_0010, 0b0000_0000]);
        assert_eq!(flags.tc, true);
    }

    #[test]
    fn flag_rd() {
        let flags = Flags::new([0b0000_0001, 0b0000_0000]);
        assert_eq!(flags.rd, true);
    }

    #[test]
    fn flag_ra() {
        let flags = Flags::new([0b0000_0000, 0b1000_0000]);
        assert_eq!(flags.ra, true);
    }

    #[test]
    fn flag_z() {
        let flags = Flags::new([0b0000_0000, 0b0111_0000]);
        assert_eq!(flags.z, 7);
    }

    #[test]
    fn flag_rcode() {
        let flags = Flags::new([0b0000_0000, 0b0000_1111]);
        assert_eq!(flags.rcode, 15);
    }
}
