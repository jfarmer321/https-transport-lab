import struct
import tempfile
import unittest
from pathlib import Path

from lab import MESSAGE, REQUEST, RESPONSE, run
from pcap import checksum


def streams(path, server_port):
    """Read each generated frame and rebuild its two TCP byte streams."""
    data = path.read_bytes()
    header = struct.unpack_from("<IHHIIII", data)
    assert header[:3] == (0xA1B2C3D4, 2, 4) and header[-1] == 101
    cursor = 24
    outbound, inbound = bytearray(), bytearray()
    while cursor < len(data):
        _, _, size, original = struct.unpack_from("<IIII", data, cursor)
        cursor += 16
        packet = data[cursor:cursor + size]
        cursor += size
        assert original == len(packet)
        assert len(packet) == struct.unpack_from("!H", packet, 2)[0]
        assert checksum(packet[:20]) == 0
        segment = packet[20:]
        pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(segment))
        assert checksum(pseudo + segment) == 0
        source, destination = struct.unpack_from("!HH", segment)
        assert {source, destination} == {49152, server_port}
        (outbound if destination == server_port else inbound).extend(segment[20:])
    assert cursor == len(data)
    return bytes(outbound), bytes(inbound)


def record_types(stream):
    cursor = 0
    types = []
    while cursor < len(stream):
        kind, major, _, length = struct.unpack_from("!BBBH", stream, cursor)
        assert major == 3 and length > 0
        types.append(kind)
        cursor += 5 + length
    assert cursor == len(stream)
    return types


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        cls.results = run(cls.output)

    def test_http_pcap_contains_exact_request_and_response(self):
        outgoing, incoming = streams(self.output / "http.pcap", 80)
        self.assertEqual(outgoing, REQUEST)
        self.assertEqual(incoming, RESPONSE)

    def test_https_pcap_has_tls_records_and_no_plaintext_marker(self):
        outgoing, incoming = streams(self.output / "https.pcap", 443)
        for direction in (outgoing, incoming):
            self.assertIn(22, record_types(direction))  # Handshake
            self.assertIn(23, record_types(direction))  # Protected records
            self.assertNotIn(MESSAGE, direction)
        self.assertNotIn(b"POST /note", outgoing)

    def test_endpoint_delivery_verified(self):
        self.assertIn("PASS | The HTTPS endpoints received the exact request and response", self.results)

    def test_untrusted_issuer_rejected(self):
        self.assertIn("PASS | Untrusted issuer rejected:", self.results)

    def test_wrong_hostname_rejected_even_with_trusted_issuer(self):
        self.assertIn("PASS | Wrong hostname rejected despite trusting the issuer:", self.results)

    def test_only_expected_artifacts_are_exported(self):
        self.assertEqual({p.name for p in self.output.iterdir()},
                         {"http.pcap", "https.pcap", "results.txt"})


if __name__ == "__main__":
    unittest.main()
