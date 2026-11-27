# Lab notes: Testing What HTTPS Protects

## Why compare these?

I wanted an example where I could point to the exact thing HTTPS changes. It is easy to say “HTTPS encrypts traffic,” but that leaves out an important question: how does the client know it is encrypting traffic to the right server?

## What the lab does

1. The HTTP example uses a small POST request to `/note` with the fake body `transport-lab-note-7d31`.
2. The HTTPS example passes that same request and response through a TLS connection between two Python endpoints. That keeps the input the same so the layer carrying it is the main difference.
3. The first HTTPS connection trusts the temporary lab CA and checks that the certificate matches `lab.example`. Two other attempts change one condition at a time: first the client does not trust the issuer, then it trusts the issuer but expects `wrong.example`.
4. The program saves the normal HTTP and HTTPS exchanges as two separate files. It wraps the bytes in synthetic TCP/IP frames so they can be inspected with Wireshark without capturing anybody's traffic. The two rejected certificate attempts are documented in the result log, not in the PCAPs.

## What the evidence showed

| Question | Evidence | Result |
| --- | --- | --- |
| Can I read the body in HTTP? | [HTTP trace](evidence/http.pcap) | The body and request path are readable. |
| Can I read it in the HTTPS transport bytes? | [HTTPS trace](evidence/https.pcap) | The raw TCP payload contains TLS records, not a readable HTTP request. |
| Did the fake message get through at all? | [Run log](evidence/results.txt) | Both HTTPS endpoints recovered the exact bytes they were supposed to receive. |
| Can the client connect without trusting the issuer? | Run log | No. The client rejected the certificate in the handshake. |
| Is a trusted issuer by itself enough? | Run log | No. The wrong hostname also failed verification. |

The third check matters. If the server never got the message, not finding it in the trace would not show much. The successful exchange confirms that the same bytes made it through TLS while remaining unreadable in the TCP stream.

## Where this is useful

This is the kind of check I would use when troubleshooting a service or reviewing a new internal app. On the network side, I'd look for an unexpected plaintext request. On the configuration side, I'd check that the client rejects an unexpected certificate instead of telling people to click through a warning.

HTTPS does not hide everything: someone looking at the traffic can still see information like the addresses, ports, and sizes. It also does not protect plaintext once it reaches an endpoint, and it does not tell you anything about password storage. That's a separate question from [whether a compromised password is enough to sign in](https://github.com/jfarmer321/admin-mfa-lab).

This lab does not attempt an interception, test a real website, or model realistic packet timing. It illustrates what the transport carries and what certificate checks this client enforces.

**References:** [Wireshark: Following Protocol Streams](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html), [RFC 5246: TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246), and [RFC 9525: Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html).
