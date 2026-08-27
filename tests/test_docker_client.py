from forgeguard.docker_client import parse_container


def test_parse_container_normalizes_docker_inspect_data() -> None:
    raw = {
        "Id": "abc123",
        "Name": "/rangeforge-dvwa",
        "Config": {
            "Image": "ghcr.io/digininja/dvwa@sha256:example",
        },
        "HostConfig": {
            "Privileged": False,
            "NetworkMode": "rangeforge-lab",
            "RestartPolicy": {"Name": "no"},
            "CapAdd": ["NET_ADMIN"],
            "SecurityOpt": ["no-new-privileges:true"],
        },
        "NetworkSettings": {
            "Ports": {
                "80/tcp": [
                    {
                        "HostIp": "127.0.0.1",
                        "HostPort": "8080",
                    }
                ],
                "443/tcp": None,
            }
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": "/srv/example",
                "Destination": "/data",
                "RW": False,
            }
        ],
    }

    container = parse_container(raw)

    assert container.container_id == "abc123"
    assert container.name == "rangeforge-dvwa"
    assert container.privileged is False
    assert container.network_mode == "rangeforge-lab"
    assert container.restart_policy == "no"
    assert container.port_bindings[0].host_ip == "127.0.0.1"
    assert container.port_bindings[0].host_port == "8080"
    assert container.mounts[0].read_only is True
    assert container.added_capabilities == ("NET_ADMIN",)
    assert container.security_options == ("no-new-privileges:true",)