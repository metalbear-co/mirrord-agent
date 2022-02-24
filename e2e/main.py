import json
import random
import string
import sys
import time
import os

import httpx
from kubernetes import client, config, watch
from pydantic import BaseModel


class InfoMessage(BaseModel):
    content: str


class ConnectedData(BaseModel):
    connection_id: int
    port: int


class ConnectedMessage(BaseModel):
    content: ConnectedData


class Data(BaseModel):
    connection_id: int
    data: str


class DataMessage(BaseModel):
    content: Data


class TCPEndedData(BaseModel):
    connection_id: int


class TCPEndedMessage(BaseModel):
    content: TCPEndedData


def create_pod_definition(container_id: str):
    return client.V1Pod(
        metadata=client.V1ObjectMeta(name="agentpod"),
        spec=client.V1PodSpec(
            host_ipc=True,
            host_pid=True,
            volumes=[
                client.V1Volume(
                    name="containerd",
                    host_path=client.V1HostPathVolumeSource(
                        path="/run/containerd/containerd.sock"
                    ),
                )
            ],
            containers=[
                client.V1Container(
                    name="mirrord-agent",
                    image=f"ghcr.io/metalbear-co/mirrord-agent-ci:{os.environ['GITHUB_SHA']}",
                    security_context=client.V1SecurityContext(privileged=True),
                    volume_mounts=[
                        client.V1VolumeMount(
                            name="containerd",
                            mount_path="/var/run/containerd/containerd.sock",
                        )
                    ],
                    command=[
                        "./mirrord-agent",
                        "--container-id",
                        container_id,
                        "--ports",
                        "80",
                    ],
                )
            ],
        ),
    )


def generate_data():
    # generate random string
    return "".join(random.choice(string.ascii_letters) for i in range(10))


def send_request(service_url: str, data: str):
    return httpx.post(service_url, json={"data": data})


def main():
    service_url = sys.argv[1]

    config.load_kube_config()
    v1 = client.CoreV1Api()

    # Get container id
    pods = v1.list_namespaced_pod("default", label_selector="app=nginx").items
    container_id = (
        pods[0].status.container_statuses[0].container_id.replace("containerd://", "")
    )

    # Create agentpod
    pod = create_pod_definition(container_id)
    v1.create_namespaced_pod("default", pod)

    # Wait for agentpod to start
    for _ in range(60):
        pod = v1.read_namespaced_pod_status("agentpod", "default")
        if pod.status.phase == "Running":
            break
        time.sleep(1)
    else:
        raise Exception("Agent pod is not running")

    # Send requests
    for _ in range(10):
        data = generate_data()
        r = send_request(service_url, data).request

    # Assert data
    logs = v1.read_namespaced_pod_log(name="agentpod", namespace="default")
    messages = []
    count_tcp_ended = 0
    count_info_message = 0
    count_connected = 0
    count_data = 0
    for log in logs.split("\n"):
        if not log:
            continue
        parsed = json.loads(log)
        if parsed["type"] == "InfoMessage":
            messages.append(InfoMessage.parse_obj(parsed))
            count_info_message += 1
        elif parsed["type"] == "Connected":
            messages.append(ConnectedMessage.parse_obj(parsed))
            count_connected += 1
        elif parsed["type"] == "Data":
            messages.append(DataMessage.parse_obj(parsed))
            count_data += 1
        elif parsed["type"] == "TCPEnded":
            messages.append(TCPEndedMessage.parse_obj(parsed))
            count_tcp_ended += 1

    assert count_tcp_ended == 10
    assert count_connected == 10
    assert count_info_message == 4
    # We can't guarantee if it might be more than 1 message per request.
    assert count_data > 10


if __name__ == "__main__":
    main()
