"""The Modbus write adapter must actually reach a server, not fail politely.

A unit identifier passed under a keyword the client library no longer accepts
raises ``TypeError`` before any frame is sent, and the handler returns it as a
clean ``{"success": false}``. The tool then looks installed and reports a
failure on every target, which no inventory-level test can see. These tests run
the real client against an in-process server on the loopback interface.
"""
from __future__ import annotations

import asyncio
import json
import warnings

import pytest

pytest.importorskip("pymodbus")

from src.agent.tools.recon_tools import modbus_write  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")


def _served(unit_ids, address, handler):
    """Run ``handler`` against a server on the loopback, return its result."""
    from pymodbus.datastore import (
        ModbusDeviceContext, ModbusSequentialDataBlock, ModbusServerContext,
    )
    from pymodbus.server import ModbusTcpServer

    warnings.filterwarnings("ignore")

    async def main():
        devices = {unit: ModbusDeviceContext(hr=ModbusSequentialDataBlock(1, [0] * 120))
                   for unit in unit_ids}
        server = ModbusTcpServer(ModbusServerContext(devices=devices, single=False),
                                 address=("127.0.0.1", address), identity=None)
        task = asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.3)
        # The handler and the verification must share one running server: a
        # second server on the same address would read a fresh datastore and
        # make a correct write look lost.
        try:
            return await asyncio.to_thread(handler)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return asyncio.run(main())


def _read(port, unit, register):
    from pymodbus.client import ModbusTcpClient

    client = ModbusTcpClient("127.0.0.1", port=port)
    assert client.connect()
    try:
        response = client.read_holding_registers(register, count=1, device_id=unit)
        assert not response.isError(), response
        return response.registers[0]
    finally:
        client.close()


def _free_port():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_modbus_write_reaches_the_server_under_its_declared_unit():
    port = _free_port()

    def handler():
        result = modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=7)
        return json.loads(result), _read(port, 7, 100)

    payload, stored = _served([7], port, handler)
    assert payload["success"] is True, payload
    assert stored == 1234


def test_modbus_write_leaves_neighbouring_registers_untouched():
    """A wrong offset or unit would be invisible in the result string alone."""
    port = _free_port()

    def handler():
        result = modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=7)
        return json.loads(result), [_read(port, 7, register) for register in (99, 100, 101)]

    payload, neighbours = _served([7], port, handler)
    assert payload["success"] is True, payload
    assert neighbours == [0, 1234, 0]


def test_modbus_write_reports_a_server_error_for_an_undeclared_unit():
    """A real protocol refusal stays a failure: the fix must not mask errors."""
    port = _free_port()
    result = _served([7], port, lambda: modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=9))
    payload = json.loads(result)
    assert payload["success"] is False
    assert "TypeError" not in payload["error"]
