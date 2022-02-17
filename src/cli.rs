use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Container id to get traffic from
    #[clap(short, long)]
    pub container_id: String,

    /// Ports to get traffic from
    #[clap(short, long)]
    pub ports: Vec<u16>,
}

pub fn parse_args() -> Args {
    Args::parse()
}
