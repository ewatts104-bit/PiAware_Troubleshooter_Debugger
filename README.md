# PiAware RTL-SDR Troubleshooter

A single-page web dashboard for real-time debugging and troubleshooting of RTL-SDR / PiAware ADS-B + UAT 978 setups on Raspberry Pi. Designed for experts — no hand-holding, full terminal access, instant toolkit actions.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Live Dashboard** — RTL-SDR detection, PiAware / dump1090-fa / dump978-fa service status, CPU temp, throttle flags, ADS-B signal stats, system resources — auto-refreshes every 5 seconds
- **Dual Gain Sliders** — independent gain control for both dongles (1090 MHz and 978 MHz UAT), snaps to valid RTL2838 gain steps, persists to `/boot/piaware-config.txt` and restarts the relevant service automatically
- **Live Log Viewer** — tail `-f` style streaming for piaware.log, dump1090-fa, syslog via SSE; one-click clear and download
- **Journal Streaming** — live `journalctl -f` for piaware and dump1090-fa
- **Expert Web Console** — full xterm.js terminal over WebSocket with a real PTY bash session; command history, copy, clear
- **One-Click Toolkit** — pre-built actions: rtl_test, EEPROM read, PPM error test, gain sweep, USB tree, dmesg filter, driver/blacklist check, ADS-B signal quality report, Pi quirks check (Pi 4/5/CM4 USB3 interference), USB power event analysis, system info
- **Config Editor** — view and edit `/etc/piaware.conf` and `/etc/default/dump1090-fa` with safe apply via `sudo tee`
- **Service Control** — restart piaware, dump1090-fa, dump978-fa from the dashboard
- **Mobile Friendly** — Bootstrap 5.3 dark terminal theme, fully responsive for phone debugging

## Requirements

- Raspberry Pi (3/4/5/CM4) running PiAware
- Python 3.11+
- One or two RTL-SDR dongles (tested with RTL2838 / RTL-SDR V4)
- `dump1090-fa` and optionally `dump978-fa` installed

## Quick Install

```bash
# On your Pi
git clone https://github.com/ewatts104-bit/PiAware_Troubleshooter_Debugger.git
cd PiAware_Troubleshooter_Debugger
bash install.sh
```

The installer:
1. Creates `/opt/piaware-troubleshooter/` and a Python venv
2. Installs the sudoers config (`/etc/sudoers.d/piaware-troubleshooter`)
3. Installs and enables the systemd service
4. Starts the app on **port 8081**

Then open: `http://<your-pi-ip>:8081`

> Port 8081 is used intentionally — port 8080 is already used by the PiAware configurator.

## Manual Run

```bash
cd /opt/piaware-troubleshooter
source venv/bin/activate
python app.py
```

## Service Management

```bash
sudo systemctl status piaware-troubleshooter
sudo systemctl restart piaware-troubleshooter
sudo journalctl -u piaware-troubleshooter -f
```

## Gain Sliders

Gain is read from and written to `/boot/piaware-config.txt` — the persistent PiAware config that survives reboots. The `/etc/default/` files are regenerated on boot and are not used for gain persistence.

Valid gain steps are the standard RTL2838 hardware steps:
`0.0, 0.9, 1.4, 2.7, 3.7, 7.7, 8.7, 12.5, 14.4, 15.7, 16.6, 19.7, 20.7, 22.9, 25.4, 28.0, 29.7, 32.8, 33.8, 36.4, 37.2, 38.6, 40.2, 42.1, 43.4, 43.9, 44.5, 48.0, 49.6`

The slider snaps to the nearest valid step on release. Changing gain restarts the relevant service (`dump1090-fa` for 1090, `dump978-fa` for 978).

**Tuning tips:**
- Strong signals > 5% of messages → lower gain
- Noise floor > −20 dBFS → USB 3.0 interference likely; move dongle to a USB 2.0 port
- Start around 40 dB for a typical rooftop antenna; lower if airport is nearby

## Nginx Reverse Proxy (optional)

To expose on port 80 with a path prefix:

```nginx
location /rtl/ {
    proxy_pass http://127.0.0.1:8081/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_read_timeout 86400;
}
```

The WebSocket upgrade headers are required for the xterm.js console.

## Security Notes

- Runs as the `pi` user — not root
- Passwordless sudo is granted only for the specific commands listed in `deploy/sudoers.d/piaware-troubleshooter`
- Custom console commands are validated against a regex whitelist before being sent to the PTY
- Rate limiting is applied to all API endpoints and PTY input (64 KB/s cap)
- Intended for use on a trusted local network — do not expose to the public internet without adding authentication

## Stack

| Component | Role |
|---|---|
| Flask 3.x | Web framework |
| Flask-SocketIO + eventlet | WebSocket server (required for xterm.js terminal) |
| xterm.js 5.3 | Browser terminal emulator |
| Bootstrap 5.3 | UI framework (dark theme) |
| psutil | CPU / memory / disk stats |
| Flask-Limiter | API rate limiting |

## License

MIT — free to use, no copyright. See [LICENSE](LICENSE)
