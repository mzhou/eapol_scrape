use anyhow::{Context, Result};
use clap::Parser;
use pcap::{Active, Capture, Device};
use pnet::datalink::MacAddr;
use pnet::packet::ethernet::{EtherType, Ethernet, MutableEthernetPacket};
use pnet::packet::Packet;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, required = true)]
    destination: MacAddr,
    #[arg(long, required = true)]
    interface: String,
    #[arg(long, required = true)]
    source: MacAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let device = Device::list()
        .context("Couldn't list devices")?
        .into_iter()
        .find(|d| d.name == args.interface)
        .context("Interface not found")?;

    let mut capture: Capture<Active> = device.open().context("Couldn't open device")?;

    capture
        .filter("ether proto 0x888e", true)
        .context("Couldn't apply filter")?;

    let id = 0x00u8;

    let request_identity = Ethernet {
        destination: args.destination,
        source: args.source,
        ethertype: EtherType::new(0x888e),
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
        ],
    };

    let mut request_identity_packet = MutableEthernetPacket::owned(vec![
            0u8;
            MutableEthernetPacket::packet_size(&request_identity)
        ])
    .context("Couldn't allocate MutableEthernetPacket")?;
    request_identity_packet.populate(&request_identity);

    capture
        .sendpacket(request_identity_packet.packet())
        .context("sendpacket failed")?;

    Ok(())
}
