use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPConnected {
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPData {
    data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Event {
    Connected(TCPConnected),
    Data(TCPData),
}
