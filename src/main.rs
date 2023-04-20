use anyhow::{Context, Result};
use clap::Parser;
use pcap::{Active, Capture, Device};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, required = true)]
    interface: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let device = Device::list()
        .context("Couldn't list devices")?
        .into_iter()
        .find(|d| d.name == args.interface)
        .context("Interface not found")?;

    let mut capture: Capture<Active> = device.open().context("Couldn't open device")?;

    capture.filter("eapol", true).context("Couldn't apply filter")?;

    Ok(())
}
