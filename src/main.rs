#![allow(clippy::unused_io_amount)]
use std::{io::Result, net::UdpSocket};

mod packets;
use packets::parsed::Packet;
use packets::raw::RawPacket;

use crate::packets::parts::QueryType;

fn main() -> Result<()> {
    let qname = "google.com";
    let qtype = QueryType::A;
    let server = ("8.8.8.8", 53);

    let socket = UdpSocket::bind(("0.0.0.0", 12345))?;

    let mut packet = Packet::empty();

    packet.header.id = 1234;
    packet.header.qdcount = 1;
    packet.header.flags.rd = true;
    packet
        .questions
        .push(packets::parts::Question::new(qname.to_string(), qtype, 1));

    let raw_packet = RawPacket::from_packet(&packet);

    socket.send_to(&raw_packet.buffer, server)?;

    let mut recv_packet = RawPacket::new();

    socket.recv(&mut recv_packet.buffer)?;

    let packet = Packet::from_raw_packet(&mut recv_packet);

    println!("{:?}", packet);

    socket.send_to(&raw_packet.buffer, server)?;

    Ok(())
}
