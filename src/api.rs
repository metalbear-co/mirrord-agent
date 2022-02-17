use serde::{Deserialize, Serialize};

pub type ConnectionID = u64;

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPConnected {
    pub connection_id: ConnectionID,
    pub port: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPData {
    pub connection_id: ConnectionID,
    pub data: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TCPEnded {
    pub connection_id: ConnectionID,
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
#[serde(tag = "type", content = "content")]
pub enum Event {
    Connected(TCPConnected),
    InfoMessage(String),
    TCPEnded(TCPEnded),
    Data(TCPData),
    Error(AgentError),
    Done,
}
