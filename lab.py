"""Compare direct HTTP and TLS endpoints entirely in memory."""
import argparse
import os
import ssl
import subprocess
import tempfile
from pathlib import Path

from pcap import write_trace

HOST = "lab.example"
MESSAGE = b"transport-lab-note-7d31"
REQUEST = (
    b"POST /note HTTP/1.1\r\nHost: lab.example\r\n"
    b"Content-Type: text/plain\r\nConnection: close\r\n"
    + f"Content-Length: {len(MESSAGE)}\r\n\r\n".encode() + MESSAGE
)
RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
NAMES = ("http.pcap", "https.pcap", "results.txt")


def contexts(directory):
    """Generate a disposable local CA and a server certificate for HOST."""
    config = directory / "extensions.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\n[dn]\n"
        "[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "[server]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:{HOST}\n"
    )

    def openssl(*args):
        subprocess.run(
            ["openssl", *args], cwd=directory, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

    openssl("req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-sha256", "-days", "2", "-subj", "/CN=Transport Lab CA",
            "-config", config.name, "-extensions", "ca",
            "-keyout", "ca.key", "-out", "ca.pem")
    openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-config", config.name, "-subj", f"/CN={HOST}",
            "-keyout", "server.key", "-out", "server.csr")
    openssl("x509", "-req", "-in", "server.csr", "-CA", "ca.pem",
            "-CAkey", "ca.key", "-set_serial", "1", "-days", "2", "-sha256",
            "-extfile", config.name, "-extensions", "server", "-out", "server.pem")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = ssl.TLSVersion.TLSv1_2
    server.load_cert_chain(directory / "server.pem", directory / "server.key")

    def client(trust):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if trust:
            ctx.load_verify_locations(cafile=directory / "ca.pem")
        return ctx

    return server, client


class LocalTLS:
    """Real TLS records exchanged directly between two SSL MemoryBIO endpoints."""

    def __init__(self, client, server, hostname):
        self.incoming = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        self.outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()]
        self.peers = [
            client.wrap_bio(self.incoming[0], self.outgoing[0], server_hostname=hostname),
            server.wrap_bio(self.incoming[1], self.outgoing[1], server_side=True),
        ]
        self.transcript = []

    def move(self, side):
        data = self.outgoing[side].read()
        if data:
            self.transcript.append((side, data))
            self.incoming[1 - side].write(data)

    def connect(self):
        ready = [False, False]
        for _ in range(30):
            for side, peer in enumerate(self.peers):
                if not ready[side]:
                    try:
                        peer.do_handshake()
                        ready[side] = True
                    except ssl.SSLWantReadError:
                        pass
                self.move(side)
            if all(ready):
                return
        raise RuntimeError("TLS handshake did not finish")

    def transfer(self, side, data):
        if self.peers[side].write(data) != len(data):
            raise RuntimeError("Unexpected partial write")
        self.move(side)
        return self.peers[1 - side].read(len(data))


    def close(self):
        closed = [False, False]
        for _ in range(10):
            for side, peer in enumerate(self.peers):
                if not closed[side]:
                    try:
                        peer.unwrap()
                        closed[side] = True
                    except ssl.SSLWantReadError:
                        pass
                self.move(side)
            if all(closed):
                return
        raise RuntimeError("TLS shutdown did not finish")


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def verify_rejection(server, client, hostname):
    try:
        LocalTLS(client, server, hostname).connect()
    except ssl.SSLCertVerificationError as error:
        return error.verify_message
    raise RuntimeError(f"Unexpected certificate acceptance for {hostname}")


def run(output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="transport-lab-") as tmp:
        server, client = contexts(Path(tmp))
        exchange = LocalTLS(client(True), server, HOST)
        exchange.connect()
        require(exchange.transfer(0, REQUEST) == REQUEST, "HTTPS request changed")
        require(exchange.transfer(1, RESPONSE) == RESPONSE, "HTTPS response changed")
        exchange.close()
        http_transcript = [(0, REQUEST), (1, RESPONSE)]
        http_bytes = b"".join(data for side, data in http_transcript if side == 0)
        tls_bytes = b"".join(data for side, data in exchange.transcript if side == 0)
        require(MESSAGE in http_bytes, "HTTP control case did not contain marker")
        require(MESSAGE not in tls_bytes, "HTTPS transport bytes contained marker")
        untrusted = verify_rejection(server, client(False), HOST)
        wrong_name = verify_rejection(server, client(True), "wrong.example")
        write_trace(output / "http.pcap", 80, http_transcript)
        write_trace(output / "https.pcap", 443, exchange.transcript)
        details = [
            "Transport lab | generated offline traces",
            f"TLS version: {exchange.peers[0].version()}",
            f"Cipher suite: {exchange.peers[0].cipher()[0]}",
            "PASS | HTTP transport contains the fake message.",
            "PASS | HTTPS transport does not contain the fake message.",
            "PASS | The HTTPS endpoints received the exact request and response.",
            f"PASS | Untrusted issuer rejected: {untrusted}",
            f"PASS | Wrong hostname rejected despite trusting the issuer: {wrong_name}",
            "PCAP timing, IP addresses, and TCP headers are synthetic.",
        ]
        results = "\n".join(details) + "\n"
        (output / "results.txt").write_text(results)
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("run-output"))
    args = parser.parse_args()
    # Never export TLS session keys through the local environment.
    os.environ.pop("SSLKEYLOGFILE", None)
    try:
        print(run(args.output), end="")
    except FileNotFoundError as error:
        parser.exit(1, f"Required command or input missing: {error}\n")
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"Local certificate generation failed: {error.stderr}\n")
