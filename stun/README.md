# ponystun - minimal STUN responder

`ponystun.py` is a tiny STUN-only responder (RFC 5389, Binding requests only) that
lets CarrierPony clients learn their public `ip:port` for direct WAN paths (UDP hole
punching). It is optional: it is only needed if you want your relay's users to be
able to set up direct peer-to-peer paths. Without it, everything still works over the
normal store-and-forward relay.

It is deliberately minimal:

- It answers only well-formed IPv4 Binding requests; anything else is dropped, so it
  cannot be used as a UDP amplifier for arbitrary traffic (the reply is 32 bytes to a
  20-byte request).
- It performs no TURN/relaying, no authentication, and keeps no logs of who asked.
- Pure Python standard library. No dependencies.

## Run it

    python3 stun/ponystun.py --host 0.0.0.0 --port 3478

## Run it as a service

    sudo mkdir -p /opt/carrierpony/stun
    sudo cp stun/ponystun.py /opt/carrierpony/stun/
    sudo cp stun/ponystun.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now ponystun

Open UDP 3478 to the internet:

    sudo ufw allow 3478/udp

## Point clients at it

In the app's direct-over-the-internet setting, the STUN server is your relay's host
on UDP 3478 (for example `relay.example.org:3478`). Signaling still rides the sealed
relay path, so the STUN server only ever reflects an address back; it never sees any
message content or who is talking to whom.
