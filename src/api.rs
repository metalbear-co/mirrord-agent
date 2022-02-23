use serde::{Deserialize, Serialize};

pub type ConnectionID = u64;

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPConnected {
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPData {
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AgentError {
    msg: String,
}

impl AgentError {
    pub fn from_error<T>(error: T) -> AgentError
    where
        T: ToString,
    {
        AgentError {
            msg: error.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Event {
    Connected(TCPConnected),
    TCPEnded,
    Data(TCPData),
    Error(AgentError),
    Done,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    pub connection_id: Option<ConnectionID>,
    pub event: Event,
}
