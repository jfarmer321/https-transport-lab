# Testing What HTTPS Protects

If I send the exact same message over HTTP and HTTPS, what can I read from the traffic? And if a server offers encryption but presents the wrong certificate, will the client still connect?

I wanted to answer those questions with two traces I could open side by side in Wireshark. I kept the message the same and ran the exchange offline, so I could focus on what TLS changed rather than the traffic around it. The [write-up](writeup.md) explains why I tested the certificate checks separately.

| Test | Result |
| --- | --- |
| HTTP request | The fake message and request path appear in plain text. |
| HTTPS with a trusted certificate for the right name | The server receives the same message, but the fake message is not readable in the trace. |
| HTTPS with an untrusted issuer | The client stops during the handshake. |
| HTTPS with a trusted issuer but the wrong hostname | The client still stops during the handshake. |

## Try it in Wireshark

1. Download [http.pcap](evidence/http.pcap) and [https.pcap](evidence/https.pcap). Open them as files in Wireshark. You don't need to start a capture.
2. In the HTTP file, filter on `tcp.port == 80`, select the POST, and choose **Follow > TCP Stream**. Find `POST /note` and the message `transport-lab-note-7d31`.
3. In the HTTPS file, filter on `tls` to find the handshake and protected records. To see the underlying bytes, follow the **TCP** stream. The fake message and HTTP path are not readable there. The IP addresses, ports, and packet sizes are still visible.

These are **generated offline traces**, not captures from a live network. The TCP/IP headers and packet timestamps are synthetic. The HTTPS record bytes come from a real TLS exchange between two in-memory endpoints.

## Reproduce the evidence

Requires Python 3.9 or later and an `openssl` command (OpenSSL or compatible LibreSSL). No Python packages, admin access, live packet capture, or system trust changes needed.

```sh
python3 lab.py
python3 -m unittest -v
```

The first command writes two PCAPs and a result log to `run-output/`. It creates a disposable certificate authority and server certificate, trusts the CA only in the lab client that needs it, and deletes the keys afterward. Cipher selection and certificate error wording may differ across machines.

- [Saved results](evidence/results.txt)
- [Write-up](writeup.md)
- [Related project: Admin MFA Lab](https://github.com/jfarmer321/admin-mfa-lab)
