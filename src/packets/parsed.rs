use super::parts::PacketHeader;
use super::parts::Question;
use super::parts::Record;
use super::raw::RawPacket;

#[derive(Debug, PartialEq)]
pub struct Packet {
    pub header: PacketHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Packet {
    pub fn from_raw_packet(packet: &mut RawPacket) -> Packet {
        let header_bytes: [u8; 12] = packet.buffer[0..12].try_into().expect("Invalid header");
        let header = PacketHeader::from_raw_header(header_bytes);

        let question_count = header.qdcount as usize;
        let questions: Vec<Question> = packet.get_questions(question_count as u16);
        let answers: Vec<Record> = packet.get_records(header.ancount);
        let authorities: Vec<Record> = packet.get_records(header.nscount);
        let additionals: Vec<Record> = packet.get_records(header.arcount);

        Packet {
            header: PacketHeader::from_raw_header(header_bytes),
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    pub fn empty() -> Packet {
        Packet {
            header: PacketHeader::empty(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.header.to_bytes());

        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }

        for answer in &self.answers {
            bytes.extend_from_slice(&answer.to_bytes());
        }

        for authority in &self.authorities {
            bytes.extend_from_slice(&authority.to_bytes());
        }

        for additional in &self.additionals {
            bytes.extend_from_slice(&additional.to_bytes());
        }

        bytes
    }
}
