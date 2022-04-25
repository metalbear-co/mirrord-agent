use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Container id to get traffic from
    #[clap(short, long)]
    pub container_id: Option<String>,


    /// Port to use for communication
    #[clap(short = 'l', long, default_value_t = 61337)]
    pub communicate_port: u16,
}

pub fn parse_args() -> Args {
    Args::parse()
}
