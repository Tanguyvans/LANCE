"""The Modbus write adapter must reach a server, and must reach the *right* register.

Two faults were found in an earlier version of these tests.

The first was a keyword: the unit identifier was passed as ``slave=``, which
pymodbus removed in favour of ``device_id=``. The client raised ``TypeError``
before any frame left and the handler returned it as a clean
``{"success": false}``, so the tool looked installed and failed everywhere.

The second was subtler and survived the first fix: the test server held
``ModbusSequentialDataBlock(1, [0] * 120)``, where every value is zero. With a
wrong address offset, writing register 100 lands on register 99, which reads
back 0 before and 1234 after, so the assertion passed while the documented
register had never been written. The server below therefore uses ``SimDevice``
with **all values distinct**, and every assertion names the value expected at
the documented address.

``ModbusSparseDataBlock`` is used instead of ``ModbusSequentialDataBlock``,
which exposes ``lo - 1`` for a block declared at ``lo``, and instead of
``SimDevice``, which accepts only a four-list tuple.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pymodbus = pytest.importorskip("pymodbus")

from src.agent.tools.recon_tools import modbus_write  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

UNIT = 7
# Distinct, non-zero values: no assertion below can pass on a shifted address.
HOLDING = {100 + index: 5000 + index for index in range(20)}
INPUTS = {100 + index: 6000 + index for index in range(20)}


def _device():
    """A device whose holding and input registers are readable as declared."""
    from pymodbus.datastore import ModbusDeviceContext, ModbusSparseDataBlock

    return ModbusDeviceContext(hr=ModbusSparseDataBlock(dict(HOLDING)),
                               ir=ModbusSparseDataBlock(dict(INPUTS)))


def _free_port():
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _raw(port, unit, function, address, count=1, value=None):
    """One MBAP request, so the test never trusts the client's own offsets."""
    import socket
    import struct

    pdu = (struct.pack(">BHH", function, address, count) if function in (3, 4)
           else struct.pack(">BHH", function, address, value))
    frame = struct.pack(">HHHB", 1, 0, len(pdu) + 1, unit) + pdu
    with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
        sock.sendall(frame)
        response = sock.recv(256)
    body = response[7:]
    if body and body[0] & 0x80:
        return {"exception": body[1]}
    return {"values": list(struct.unpack(f">{body[1] // 2}H", body[2:]))}


def _served(handler):
    """Run ``handler(port)`` against a live server, in one running loop."""
    from pymodbus.datastore import ModbusServerContext
    from pymodbus.server import ModbusTcpServer

    async def main():
        _port = _free_port()
        server = ModbusTcpServer(ModbusServerContext(devices={UNIT: _device()}, single=False),
                                 address=("127.0.0.1", _port), identity=None)
        task = asyncio.create_task(server.serve_forever())
        await asyncio.sleep(0.3)
        port = _port
        try:
            return await asyncio.to_thread(handler, port)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    return asyncio.run(main())


def test_written_value_lands_on_the_declared_register_only():
    def handler(port):
        outcome = json.loads(modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=UNIT))
        return outcome, {address: _raw(port, UNIT, 3, address) for address in (99, 100, 101)}

    outcome, neighbours = _served(handler)
    assert outcome["success"] is True, outcome
    assert neighbours[100] == {"values": [1234]}
    # 99 is outside the window and 101 keeps its own value: an offset by one
    # would put 1234 on 99 and leave 100 at 5000.
    assert neighbours[99] == {"exception": 2}
    assert neighbours[101] == {"values": [5001]}


def test_write_leaves_input_registers_untouched():
    def handler(port):
        modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=UNIT)
        return _raw(port, UNIT, 4, 100)

    assert _served(handler) == {"values": [6000]}


def test_unknown_unit_is_a_protocol_refusal_not_a_python_error():
    def handler(port):
        return json.loads(modbus_write("127.0.0.1", 100, 1234, port=port, unit_id=9))

    payload = _served(handler)
    assert payload["success"] is False
    assert "TypeError" not in payload["error"]


def test_the_server_itself_exposes_addresses_without_offset():
    """Guards the fixture: a shifted server would make the tests above vacuous."""
    def handler(port):
        return {address: _raw(port, UNIT, 3, address) for address in (99, 100, 119, 120)}

    answers = _served(handler)
    assert answers[100] == {"values": [5000]}
    assert answers[119] == {"values": [5019]}
    assert answers[99] == {"exception": 2}
    assert answers[120] == {"exception": 2}
