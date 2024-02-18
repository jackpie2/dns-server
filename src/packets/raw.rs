use std::net::Ipv4Addr;

use super::parsed::Packet;
use super::parts::QueryType;
use super::parts::Question;
use super::parts::Record;

pub struct RawPacket {
    pub buffer: [u8; 512],
    pub pos: usize,
}

impl RawPacket {
    pub fn new() -> RawPacket {
        RawPacket {
            buffer: [0; 512],
            pos: 12,
        }
    }

    pub fn from_packet(packet: &Packet) -> RawPacket {
        let mut raw_packet = RawPacket::new();

        let bytes = packet.to_bytes();

        raw_packet.buffer[..bytes.len()].copy_from_slice(&bytes);

        raw_packet
    }

    pub fn get_header(&self) -> [u8; 12] {
        self.buffer[0..12].try_into().expect("Invalid header")
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn move_by(&mut self, offset: usize) {
        self.pos += offset;
    }

    pub fn get_qname(&mut self) -> String {
        let mut qname = String::new();
        let mut pos = self.pos;
        let max_jumps = 5;
        let mut jumps = 0;
        let mut bytes_read = 0;

        loop {
            if jumps > max_jumps {
                break;
            }

            let len = self.buffer[pos] as usize;

            if len == 0 {
                break;
            }

            if (len & 0xc0) == 0xc0 {
                let b1 = self.buffer[pos] as usize;
                let b2 = self.buffer[pos + 1] as usize;
                let offset = ((b1 ^ 0b1100_0000) << 8) | b2;
                pos = offset;

                if jumps == 0 {
                    self.move_by(bytes_read + 2);
                }

                jumps += 1;
                continue;
            }

            pos += 1;

            if !qname.is_empty() {
                qname.push('.');
            }

            qname.push_str(
                &String::from_utf8(self.buffer[pos..pos + len].to_vec()).expect("Invalid UTF-8"),
            );
            pos += len;
            bytes_read += len + 1;
        }

        if jumps == 0 {
            self.seek(pos + 1);
        }

        qname
    }

    pub fn get_questions(&mut self, qdcount: u16) -> Vec<Question> {
        let mut questions = Vec::with_capacity(qdcount as usize);
        self.seek(12);

        for _ in 0..qdcount {
            let qname = self.get_qname();
            let qtype = QueryType::new(
                (self.buffer[self.pos] as u16) << 8 | self.buffer[self.pos + 1] as u16,
            );
            let qclass = (self.buffer[self.pos + 2] as u16) << 8 | self.buffer[self.pos + 3] as u16;
            self.move_by(4);
            questions.push(Question::new(qname, qtype, qclass));
        }
        questions
    }

    pub fn get_records(&mut self, count: u16) -> Vec<Record> {
        let mut records: Vec<Record> = Vec::with_capacity(count as usize);

        for _ in 0..count {
            let rname = self.get_qname();
            let rtype = QueryType::new(
                (self.buffer[self.pos] as u16) << 8 | self.buffer[self.pos + 1] as u16,
            );
            self.move_by(2);
            let rclass = (self.buffer[self.pos] as u16) << 8 | self.buffer[self.pos + 1] as u16;
            self.move_by(2);
            let ttl = (self.buffer[self.pos] as u32) << 24
                | (self.buffer[self.pos + 1] as u32) << 16
                | (self.buffer[self.pos + 2] as u32) << 8
                | self.buffer[self.pos + 3] as u32;
            self.move_by(4);
            let rlen = (self.buffer[self.pos] as u16) << 8 | self.buffer[self.pos + 1] as u16;
            self.move_by(2);

            match rtype {
                QueryType::A => {
                    let addr = Ipv4Addr::new(
                        self.buffer[self.pos],
                        self.buffer[self.pos + 1],
                        self.buffer[self.pos + 2],
                        self.buffer[self.pos + 3],
                    );
                    self.move_by(rlen as usize);
                    records.push(Record::A {
                        domain: rname,
                        addr,
                        ttl,
                    });
                }
                _ => {
                    self.move_by(rlen as usize);
                    records.push(Record::UNKNOWN {
                        domain: rname,
                        qtype: rtype.into(),
                        rlen,
                        ttl,
                    });
                }
            }
        }

        records
    }
}

#[cfg(test)]
mod tests {
    use crate::packets::{parsed, parts::Flags};

    use super::*;

    #[test]
    fn test_from_packet() {
        let mut packet = parsed::Packet::empty();
        packet.header.id = 34346;
        packet.header.flags = Flags::new([0b1000_0001, 0b1000_0000]);
        packet.header.qdcount = 1;
        packet.header.ancount = 1;
        packet.header.nscount = 0;
        packet.header.arcount = 0;
        packet
            .questions
            .push(Question::new("google.com".to_string(), QueryType::A, 1));
        packet.answers.push(Record::A {
            domain: "google.com".to_string(),
            addr: Ipv4Addr::new(216, 58, 211, 142),
            ttl: 293,
        });

        let mut raw_packet = RawPacket::from_packet(&packet);

        let packet2 = Packet::from_raw_packet(&mut raw_packet);

        assert_eq!(packet, packet2);
    }

    #[test]
    fn test_get_answer_record() {
        let mut packet = RawPacket::new();
        let raw_packet = [
            0x86, 0x2a, 0x81, 0x80, 00, 01, 00, 01, 00, 00, 00, 00, 06, b'g', b'o', b'o', b'g',
            b'l', b'e', 03, b'c', b'o', b'm', 00, 00, 01, 00, 01, 0xc0, 0x0c, 00, 01, 00, 01, 00,
            00, 01, 0x25, 00, 04, 0xd8, 0x3a, 0xd3, 0x8e,
        ];

        packet.buffer[..raw_packet.len()].copy_from_slice(&raw_packet);

        packet.get_questions(1);
        let answers = packet.get_records(1);
        let answer = &answers[0];
        match answer {
            Record::A { domain, addr, ttl } => {
                assert_eq!(domain, "google.com");
                assert_eq!(
                    addr.to_string(),
                    Ipv4Addr::new(216, 58, 211, 142).to_string()
                );
                assert_eq!(*ttl, 293);
            }
            _ => panic!("Expected A record"),
        }
    }

    #[test]
    fn test_get_header() {
        let mut packet = RawPacket::new();
        packet.buffer[0..12].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let header = packet.get_header();

        assert_eq!(header, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn test_get_qname() {
        let mut packet = RawPacket::new();
        packet.buffer[12..29].copy_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);

        let qname = packet.get_qname();

        assert_eq!(qname, "www.example.com");
    }

    #[test]
    fn test_get_questions() {
        let mut packet = RawPacket::new();
        packet.buffer[12..29].copy_from_slice(&[
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        packet.buffer[29..33].copy_from_slice(&[0, 1, 0, 1]);

        let questions = packet.get_questions(1);

        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].qname, "www.example.com");
        assert_eq!(questions[0].qtype, QueryType::A);
        assert_eq!(questions[0].qclass, 1);
    }

    #[test]
    fn get_question_jump() {
        let mut packet = RawPacket::new();
        packet.buffer[12..23].copy_from_slice(&[3, b'w', b'w', b'w', 192, 12, 0, 1, 0, 1, 0]);
        let questions = packet.get_questions(1);
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].qname, "www.www.www.www.www.www");
        assert_eq!(questions[0].qtype, QueryType::A);
        assert_eq!(questions[0].qclass, 1);
    }

    #[test]
    fn get_questions() {
        let mut packet = RawPacket::new();
        packet.buffer[12..25]
            .copy_from_slice(&[3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let questions = packet.get_questions(1);
        assert_eq!(questions.len(), 1);
        assert_eq!(questions[0].qname, "www.com");
        assert_eq!(questions[0].qtype, QueryType::A);
        assert_eq!(questions[0].qclass, 1);
    }

    #[test]
    fn parse_qname_jump() {
        let mut packet = RawPacket::new();
        packet.buffer[12..23]
            .copy_from_slice(&[0xc0, 0x12, 0x03, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0]);
        assert_eq!(packet.get_qname(), "com");
    }
}
