import subprocess
import time
import logging
import shutil
from typing import Optional
from stem.control import Controller
from stem import Signal, SocketError
import threading
from core import config

# Suppress annoying stem SocketClosed warnings on Windows
logging.getLogger('stem').setLevel(logging.CRITICAL)

_rotate_lock = threading.Lock()
_last_rotated = 0.0
_COOLDOWN_SECONDS = 15.0

# Ports to probe when looking for a running Tor control port.
# Standalone Tor uses 9051; Tor Browser uses 9151.
_CONTROL_PORT_PROBES = [9051, 9151]


def _probe_control_port(port: int) -> bool:
    """Return True if we can authenticate on the given control port."""
    try:
        with Controller.from_port(port=str(port)) as controller:  # type: ignore[arg-type]
            controller.authenticate()
        return True
    except Exception:
        return False


def start_tor_service() -> bool:
    """Check if Tor is running on the control port; start it if not.

    Probes the control port(s) defined in ``config.TOR_CONTROL_PORT`` and the
    common Tor Browser port (9151).  If none respond, looks for the ``tor``
    executable in PATH and launches it as a background process, then waits up
    to 60 seconds for bootstrapping.

    Returns:
        True if Tor is running (or was started successfully), False otherwise.
    """
    # Build the list of ports to try: configured port first, then alternates
    configured = config.TOR_CONTROL_PORT
    ports_to_try = [configured] + [p for p in _CONTROL_PORT_PROBES if p != configured]

    # ── Step 1: Check if Tor is already running ────────────────────────────
    for port in ports_to_try:
        if _probe_control_port(port):
            logging.info("[*] Tor is already running on ControlPort %d.", port)
            return True

    logging.info("[!] Tor not detected on ControlPort %d (or fallback %d). Attempting to start service...",
                configured, ports_to_try[-1] if len(ports_to_try) > 1 else configured)

    # ── Step 2: Try to start Tor from PATH ─────────────────────────────────
    tor_path = shutil.which("tor")
    if not tor_path:
        logging.error(
            "[!] 'tor' executable not found in PATH.\n"
            "    On Windows, the easiest option is to start Tor Browser and set\n"
            "    TOR_CONTROL_PORT=9151 and TOR_PROXY_PORT=9150 in core/config.py.\n"
            "    On Linux/macOS, install the standalone Tor package."
        )
        return False

    try:
        # Start Tor as a background process
        subprocess.Popen([tor_path, "--ControlPort", str(configured)],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.STDOUT)

        # Give it time to initialize and bootstrap
        controller = None
        for i in range(30):  # Wait up to 60 seconds
            time.sleep(2)
            try:
                controller = Controller.from_port(port=str(configured))  # type: ignore[arg-type]
                controller.authenticate()

                # Check bootstrap status
                bootstrap_status = controller.get_info("status/bootstrap-phase")
                if "TAG=done" in bootstrap_status:
                    logging.info("[+] Tor service started and bootstrapped successfully.")
                    controller.close()
                    return True
                else:
                    summary = bootstrap_status.split(' SUMMARY=')[1] if 'SUMMARY=' in bootstrap_status else 'in progress'
                    logging.info("...Tor bootstrapping: %s (%d/30)", summary, i + 1)
                    controller.close()
            except Exception:
                pass  # Still initializing

        logging.error("[!] Timed out waiting for Tor to bootstrap.")
        if controller:
            controller.close()
        return False
    except Exception as e:
        logging.error("[!] Failed to start Tor: %s", e)
        return False


def rotate_identity() -> bool:
    """Signal Tor to switch to a new identity (NEWNYM) for a fresh exit node.

    Rate-limited to one rotation per 15 seconds (Tor's internal rate limit).
    Thread-safe — uses a lock to serialise concurrent rotation requests.

    Returns:
        True if the NEWNYM signal was sent (or cooldown was active),
        False if the signal could not be delivered.
    """
    global _last_rotated

    with _rotate_lock:
        now = time.time()
        if now - _last_rotated < _COOLDOWN_SECONDS:
            logging.debug("[-] Identity rotation requested, but on cooldown.")
            return True  # Pretend it succeeded since we recently rotated

        # Try the configured control port first, then fallbacks
        ports_to_try = [config.TOR_CONTROL_PORT] + [p for p in _CONTROL_PORT_PROBES if p != config.TOR_CONTROL_PORT]

        for port in ports_to_try:
            try:
                with Controller.from_port(port=str(port)) as controller:  # type: ignore[arg-type]
                    controller.authenticate()
                    controller.signal('NEWNYM')  # Use string instead of Signal.NEWNYM to avoid IDE false-positive errors
                    logging.info("[*] Signal NEWNYM sent via ControlPort %d. Tor is switching identity...", port)

                _last_rotated = time.time()
                time.sleep(5)  # Give it a moment to build a new circuit
                return True
            except Exception:
                continue

        logging.error("[!] Failed to rotate identity: no accessible control port.")
        return False


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    if start_tor_service():
        logging.info("[*] System ready.")
    else:
        logging.error("[!] Critical: Tor service unavailable.")
