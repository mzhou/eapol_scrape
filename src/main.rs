use std::sync::mpsc::channel;
use std::thread::spawn;

use anyhow::{Context, Result};
use clap::Parser;
use pcap::Capture;
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, Ethernet, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{FromPacket, Packet};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, required = true)]
    authenticator: MacAddr,
    #[arg(long, required = true)]
    interface: String,
    #[arg(long, default_value_t = false)]
    start: bool,
    #[arg(long, required = true)]
    supplicant: MacAddr,
}

const ETHERTYPE_8021X: EtherType = EtherType(0x888e);

fn build_packet(e: &Ethernet) -> Option<MutableEthernetPacket<'static>> {
    let mut packet =
        MutableEthernetPacket::owned(vec![0u8; MutableEthernetPacket::packet_size(&e)])?;
    packet.populate(e);
    Some(packet)
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut capture_read = Capture::from_device(args.interface.as_str())
        .context("Capture::from_device failed for read")?
        .promisc(true)
        .open()
        .context("Capture::open failed for read")?;

    capture_read
        .filter("ether proto 0x888e", true)
        .context("Capture::filter failed for read")?;

    let (read_tx, read_rx) = channel();
    let read_thread = spawn(move || -> Result<()> {
        loop {
            let packet = capture_read.next_packet().context("next_packet failed")?;
            read_tx
                .send(packet.data.to_owned())
                .context("send failed")?;
        }
    });

    let mut capture_write = Capture::from_device(args.interface.as_str())
        .context("Capture::from_device failed for write")?
        .open()
        .context("Capture::open failed for write")?;

    if args.start {
        let start = Ethernet {
            destination: MacAddr::new(0x01, 0x80, 0xc2, 0x00, 0x00, 0x03),
            ethertype: ETHERTYPE_8021X,
            payload: vec![
                // 802.1x
                0x01, // version
                0x01, // type
                0x00, 0x00, // length
                // padding (42 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
                0x00, 0x00, // padding (2 bytes)
            ],
            source: args.supplicant,
        };

        println!("S {:?}", start);

        let start_packet = build_packet(&start).context("build_packet failed for start")?;
        capture_write
            .sendpacket(start_packet.packet())
            .context("sendpacket failed for start")?;
    }

    let id = 0x1bu8;

    let request_identity = Ethernet {
        destination: args.supplicant,
        ethertype: ETHERTYPE_8021X,
        payload: vec![
            // 802.1x
            0x01, // version
            0x00, // type
            0x00, 0x05, // length
            // EAP
            0x01, // code
            id,   // id
            0x00, 0x05, // length
            0x01, // type
            // padding (37 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, // padding (5 bytes)
        ],
        source: args.authenticator,
    };

    println!("S {:?}", request_identity);

    let request_identity_packet =
        build_packet(&request_identity).context("build_packet failed for request_identity")?;

    capture_write
        .sendpacket(request_identity_packet.packet())
        .context("sendpacket for request_identity failed")?;

    let response_identity_packet = read_rx
        .recv()
        .context("recv for response_identity failed")?;
    let response_identity = &EthernetPacket::new(&response_identity_packet)
        .context("EthernetPacket::new failed for response_identity")?
        .from_packet();

    println!("R {:?}", response_identity);

    Ok(())
}
