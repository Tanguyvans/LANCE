"""Ephemeral Mosquitto fixture; configuration is supplied only by the controller.

The two postures differ by exactly one ACL line: anonymous read access to
the private topic. ``persistence false`` keeps retained canaries in memory
only, so destroying and recreating the fixture purges every retained
message at reset; the controller must still attest that reset happened.
This module only builds configuration text and, in the laboratory,
launches the broker and seeds the retained canaries from ``/fixture.json``.
It is never imported by the auditor policies under test.
"""
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import time


# Local apt cache on the laboratory master (apt-cacher-ng), as used by the
# benchmark guests; the disposable guest reaches it through the laboratory
# gateway configured on its single interface.
APT_PROXY_URL = "http://192.168.100.200:3142"


def _checked(config):
    flaws = config["intentional_flaws"]
    if flaws not in (0, 1):
        raise ValueError("intentional_flaws must be 0 (protected) or 1 (vulnerable)")
    for field in ("public_topic", "private_topic", "control_user"):
        value = config[field]
        if not isinstance(value, str) or not value or any(char.isspace() for char in value):
            raise ValueError(f"Invalid fixture {field}")
    if config["public_topic"] == config["private_topic"]:
        raise ValueError("Public and private topics must differ")
    return config


def build_acl(config):
    """ACL text; F1 adds exactly the anonymous private-read line."""
    config = _checked(config)
    lines = ["# Anonymous subscribers: public surface only in the protected posture.",
             f"topic read {config['public_topic']}"]
    if config["intentional_flaws"] == 1:
        lines.append(f"topic read {config['private_topic']}")
    lines += [f"user {config['control_user']}",
              f"topic read {config['public_topic']}",
              f"topic read {config['private_topic']}",
              "# Fixture-only seeder; its credential never enters a public briefing.",
              "user lance-seeder",
              f"topic write {config['public_topic']}",
              f"topic write {config['private_topic']}", ""]
    return "\n".join(lines)


def build_config(config):
    """Broker configuration text with retained state kept in memory only."""
    config = _checked(config)
    address = config.get("listen_address", "127.0.0.1")
    if ipaddress.ip_address(address) not in ipaddress.ip_network("192.168.100.0/24") and address != "127.0.0.1":
        raise ValueError("Fixture listen address outside its laboratory")
    return f"""listener {config.get('port', 1883)} {address}
protocol mqtt
allow_anonymous true
password_file /run/mosquitto/passwd
acl_file /run/mosquitto/acl
persistence false
allow_zero_length_clientid false
max_keepalive 30
message_size_limit 1024
sys_interval 0
log_dest stderr
"""


def mosquitto_command(config_path="/run/mosquitto/mosquitto.conf"):
    return ["/usr/sbin/mosquitto", "-c", config_path]


def apt_proxy_config():
    return f'Acquire::http::Proxy "{APT_PROXY_URL}";\n'


def wait_for_broker(address, port, process, timeout_s=15, connect=None,
                    sleep=time.sleep, monotonic=time.monotonic):
    """Wait until the freshly started broker accepts TCP, or fail closed."""
    if connect is None:
        connect = socket.create_connection
    deadline = monotonic() + timeout_s
    while True:
        if process.poll() is not None:
            raise RuntimeError("Mosquitto broker exited before seeding")
        if monotonic() >= deadline:
            raise RuntimeError("Mosquitto broker did not listen before seeding")
        try:
            with connect((address, port), timeout=1):
                return
        except OSError:
            pass
        sleep(0.25)


def ensure_broker_binaries(proxy_path=Path("/etc/apt/apt.conf.d/99lance-apt-proxy")):
    """Use the template's Mosquitto, or install it inside this disposable guest only."""
    import shutil
    if all(shutil.which(name) for name in ("mosquitto", "mosquitto_passwd", "mosquitto_pub")):
        return "present"
    Path(proxy_path).write_text(apt_proxy_config())
    env = {"DEBIAN_FRONTEND": "noninteractive", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    subprocess.run(["apt-get", "update", "-qq"], check=True, capture_output=True, timeout=300, env=env)
    subprocess.run(["apt-get", "install", "-y", "-qq", "mosquitto", "mosquitto-clients"],
                   check=True, capture_output=True, timeout=300, env=env)
    if not all(shutil.which(name) for name in ("mosquitto", "mosquitto_passwd", "mosquitto_pub")):
        raise RuntimeError("Mosquitto binaries unavailable in fixture guest")
    return "installed_in_disposable_guest"


def main():
    config = json.loads(Path("/fixture.json").read_text())
    _checked(config)
    ensure_broker_binaries()
    runtime = Path("/run/mosquitto")
    runtime.mkdir(parents=True, mode=0o750, exist_ok=True)
    (runtime / "acl").write_text(build_acl(config))
    (runtime / "mosquitto.conf").write_text(build_config(config))
    subprocess.run(["mosquitto_passwd", "-c", "-b", str(runtime / "passwd"),
                    config["control_user"], config["control_password"]],
                   check=True, capture_output=True)
    subprocess.run(["mosquitto_passwd", "-b", str(runtime / "passwd"),
                    "lance-seeder", config["seeder_password"]],
                   check=True, capture_output=True)
    broker = subprocess.Popen(mosquitto_command(str(runtime / "mosquitto.conf")))
    try:
        wait_for_broker(config.get("listen_address", "127.0.0.1"), config.get("port", 1883), broker)
        for topic, payload in (("public_topic", "public_canary"),
                               ("private_topic", "private_canary")):
            subprocess.run(["mosquitto_pub", "-h", config.get("listen_address", "127.0.0.1"),
                            "-p", str(config.get("port", 1883)),
                            "-u", "lance-seeder", "-P", config["seeder_password"],
                            "-t", config[topic], "-m", config[payload], "-r", "-q", "1"],
                           check=True, capture_output=True, timeout=10)
    except Exception:
        broker.terminate()
        raise
    broker.wait()


if __name__ == "__main__":
    main()
