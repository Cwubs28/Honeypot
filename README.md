# SSH Honeypot

A fake SSH service written in Python that listens for incoming connections
and logs info about them. Nothing real runs behind it - there's no
actual SSH server, no real login, this is just for simulation.

## Why I built this

This completes a three-part detection pipeline alongside my other two
projects:

1. **[port-scanner](https://github.com/Cwubs28/port-scanner)** — finds what's exposed on a system (reconnaissance)
2. **honeypot (this repo)** — attracts and logs connection attempts in real time (active collection)
3. **[failed-login-detector](https://github.com/Cwubs28/failed-login-detector)** — analyzes logs after the fact and flags brute-force patterns (detection)

The honeypot writes its logs in the exact same format as a real SSH auth
log, which means the failed-login-detector can analyze this honeypot's
output directly, with zero modification. I tested this end-to-end: ran the
honeypot, generated some connection attempts, then pointed the existing
detector at the honeypot's log file and it correctly flagged the source as
a brute-force pattern. The three tools form a working pipeline, not just
three separate scripts.

## Safety note

I bound this to `127.0.0.1` (localhost) by default, meaning **only my own
machine can connect to it** — it's not exposed to the internet or my local
network. That makes it safe to run for testing, observation, and portfolio
purposes. 

## What it does

- Opens a fake SSH service on a chosen port (default: 2222)
- Sends a realistic SSH version banner to anything that connects
- Logs every connection attempt: source IP, port, and timestamp
- Writes logs in standard SSH auth log format, making them directly
  compatible with my failed-login-detector project
- Handles multiple simultaneous connections using threading

## How to run it

```bash
# Start the honeypot (binds to localhost:2222 by default)
python3 honeypot.py

# Use a different port
python3 honeypot.py --port 2222

# Change where logs are saved
python3 honeypot.py --port 2222 --log honeypot.log
```

While it's running, it waits for connections and logs each one. Stop it
anytime with `Ctrl+C`.

## Testing it locally

I opened a second terminal and connected to it manually:

```bash
telnet 127.0.0.1 2222
```

A fake SSH banner comes back, and the honeypot's terminal shows the
connection was logged.

## Full pipeline test

```bash
# 1. Run the honeypot and let it collect some connection attempts
python3 honeypot.py --port 2222 --log honeypot.log

# 2. In another terminal, point the failed-login-detector at the honeypot's log
python3 failed_login_detector.py honeypot.log --threshold 2
```

See `honeypot-listening.png` and `pipeline-detection-output.png` below for
my actual tested output.

![Honeypot logging connections](./Screenshot%20Honeypot-listening.png)
![Pipeline detection output](./Screenshot%20pipeline-detection-output.png)

## How it works

1. **Listening socket** — opens a TCP socket and waits for incoming
   connections, same underlying mechanism as any real server.
2. **Fake banner** — sends back a realistic SSH version string
   (`SSH-2.0-OpenSSH_8.9`) so the interaction looks convincing to anything
   probing the port.
3. **Threading** — each connection is handled on its own thread, so the
   honeypot can log multiple simultaneous connection attempts without one
   slow connection blocking the others.
4. **Compatible logging** — every connection attempt is written in the
   same format a real SSH server's auth log would use, which is what
   makes it a drop-in input for the failed-login-detector.

## Skills demonstrated

- Socket programming (server-side: binding, listening, accepting connections)
- Multi-threaded connection handling
- Security concept: honeypots / deception-based detection
- Log format design for compatability between tools

## Possible next steps

- Simulate a fake shell prompt after connection to keep attackers engaged
  longer and collect more behavioral data 
- Add support for logging on multiple fake ports at once (FTP, Telnet, etc.)
- Deploy on a cloud VM with a public IP to attract and study real internet
  scanning traffic 
