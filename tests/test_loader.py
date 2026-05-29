"""Tests for YAML loading, graph queries, and attack surface."""

from pathlib import Path

import pytest

from src.loader import build_graph, load_yaml

YAML_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"


@pytest.fixture
def backend():
    return build_graph(YAML_PATH)


@pytest.fixture
def infra():
    return load_yaml(YAML_PATH)


# ------------------------------------------------------------------
# YAML loading
# ------------------------------------------------------------------

class TestYAMLLoading:
    def test_loads_without_error(self, infra):
        assert infra is not None
        assert infra.metadata["name"] == "Smart City IoT Lab (representative topology)"

    def test_device_count(self, infra):
        # 15 devices: mikrotik, netgear, jetson, cam_turret, nvr, rpi5,
        # iot_hub, wisgate, eap613, em310, sensecap, elsys, dragino,
        # aqara_vib, aqara_door
        assert len(infra.devices) == 15

    def test_link_count(self, infra):
        assert len(infra.links) == 16

    def test_network_count(self, infra):
        assert len(infra.networks) == 1

    def test_external_count(self, infra):
        assert len(infra.external) == 1

    def test_mikrotik_version(self, infra):
        mikrotik = next(d for d in infra.devices if d.id == "mikrotik")
        assert mikrotik.os_version == "7.18.2"

    def test_jetson_firmware(self, infra):
        jetson = next(d for d in infra.devices if d.id == "jetson")
        assert jetson.firmware == "JetPack R36.4.7"
        assert jetson.os_version == "22.04.5"


# ------------------------------------------------------------------
# Graph backend
# ------------------------------------------------------------------

class TestGraphBackend:
    def test_graph_stats_nodes(self, backend):
        stats = backend.get_graph_stats()
        # 15 devices + 1 external entity
        assert stats["nodes"] == 16

    def test_graph_stats_edges(self, backend):
        stats = backend.get_graph_stats()
        assert stats["edges"] == 16

    def test_graph_is_connected(self, backend):
        stats = backend.get_graph_stats()
        assert stats["is_connected"] is True

    def test_get_device(self, backend):
        dev = backend.get_device("mikrotik")
        assert dev["name"] == "MikroTik RB5009"
        assert dev["type"] == "router"
        assert dev["os_version"] == "7.18.2"

    def test_neighbors_netgear(self, backend):
        neighbors = backend.get_neighbors("netgear")
        expected = {"mikrotik", "jetson", "rpi5", "wisgate", "eap613",
                    "cam_turret", "iot_hub", "nvr"}
        assert set(neighbors) == expected

    def test_path_em310_to_rpi5(self, backend):
        paths = backend.find_all_paths("em310", "rpi5")
        assert len(paths) > 0
        # Direct path: em310 → wisgate → rpi5 (via MQTT)
        assert ["em310", "wisgate", "rpi5"] in paths

    def test_path_aqara_to_rpi5(self, backend):
        paths = backend.find_all_paths("aqara_vib", "rpi5")
        assert len(paths) > 0
        assert ["aqara_vib", "rpi5"] in paths

    def test_mqtt_broker_is_rpi5(self, backend):
        dev = backend.get_device("rpi5")
        mqtt_services = [s for s in dev["services"] if s["name"] == "mqtt"]
        assert len(mqtt_services) == 1
        assert mqtt_services[0]["version"] == "Mosquitto 2.0.21"


# ------------------------------------------------------------------
# Attack surface
# ------------------------------------------------------------------

class TestAttackSurface:
    def test_attack_surface_not_empty(self, backend):
        surface = backend.get_attack_surface()
        assert len(surface) > 0

    def test_attack_surface_contains_mikrotik(self, backend):
        surface = backend.get_attack_surface()
        ids = [d["id"] for d in surface]
        assert "mikrotik" in ids

    def test_attack_surface_devices_have_services(self, backend):
        surface = backend.get_attack_surface()
        for device in surface:
            assert len(device["services"]) > 0

    def test_sensors_not_in_attack_surface(self, backend):
        surface = backend.get_attack_surface()
        ids = [d["id"] for d in surface]
        for sensor_id in ("em310", "sensecap", "elsys", "dragino", "aqara_vib", "aqara_door"):
            assert sensor_id not in ids


# ------------------------------------------------------------------
# Export
# ------------------------------------------------------------------

class TestExport:
    def test_to_dict_structure(self, backend):
        data = backend.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 16
        assert len(data["edges"]) == 16
