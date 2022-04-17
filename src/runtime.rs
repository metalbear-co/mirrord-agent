use nix::sched::setns;
use std::os::unix::io::{IntoRawFd, RawFd};

use anyhow::{anyhow, Result};
use containerd_client::services::v1::containers_client::ContainersClient;
use containerd_client::services::v1::GetContainerRequest;
use containerd_client::{connect, with_namespace};
use std::fs::File;

use serde::{Deserialize, Serialize};
use tonic::Request;

const CONTAINERD_SOCK_PATH: &str = "/run/containerd/containerd.sock";
const DEFAULT_CONTAINERD_NAMESPACE: &str = "k8s.io";

#[derive(Serialize, Deserialize, Debug)]
struct Namespace {
    #[serde(rename = "type")]
    ns_type: String,
    path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct LinuxInfo {
    namespaces: Vec<Namespace>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Spec {
    linux: LinuxInfo,
}

pub fn set_namespace(ns_path: &str) -> Result<()> {
    let fd: RawFd = File::open(ns_path)?.into_raw_fd();
    setns(fd, nix::sched::CloneFlags::CLONE_NEWNET)?;
    Ok(())
}

pub async fn get_container_namespace(container_id: String) -> Result<String> {
    let channel = connect(CONTAINERD_SOCK_PATH).await?;
    let mut client = ContainersClient::new(channel);
    let request = GetContainerRequest { id: container_id };
    let request = with_namespace!(request, DEFAULT_CONTAINERD_NAMESPACE);
    let resp = client.get(request).await?;
    let resp = resp.into_inner();
    let container = resp
        .container
        .ok_or_else(|| anyhow!("container not found"))?;
    let spec: Spec = serde_json::from_slice(
        &container
            .spec
            .ok_or_else(|| anyhow!("invalid data from containerd"))?
            .value,
    )?;
    let ns_path = spec
        .linux
        .namespaces
        .iter()
        .find(|ns| ns.ns_type == "network")
        .ok_or_else(|| anyhow!("network namespace not found"))?
        .path
        .as_ref()
        .ok_or_else(|| anyhow!("no network namespace path"))?;
    Ok(ns_path.to_owned())
}
