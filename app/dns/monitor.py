"""
DNS Traffic Monitor - Lab Environment Only.
Monitors DNS traffic in an isolated lab network.
"""
import logging
import threading
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime

# Try to import scapy for live capture
try:
    from scapy.all import sniff, DNS, IP, IPv6, UDP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    get_if_list = lambda: []

from app.database.database import get_db_session
from app.detection.engine import analyze_dns_event

logger = logging.getLogger(__name__)


def get_available_interfaces() -> List[str]:
    """Get list of available network interfaces for Kali Linux/Linux/Windows."""
    interfaces = []
    if SCAPY_AVAILABLE:
        try:
            interfaces = get_if_list()
        except Exception as e:
            logger.warning(f"Error fetching interfaces from Scapy: {e}")

    # Additional fallback methods for Kali Linux
    if not interfaces:
        # Method 1: /proc/net/dev
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        iface = line.split(':')[0].strip()
                        if iface and iface not in ['lo', 'sit0']:
                            interfaces.append(iface)
        except Exception:
            pass

    # Method 2: socket.if_nameindex (Linux)
    if not interfaces:
        try:
            import socket
            if hasattr(socket, 'if_nameindex'):
                interfaces = [name for idx, name in socket.if_nameindex()]
        except Exception:
            pass

    # Method 3: ip command (modern Linux)
    if not interfaces:
        try:
            import subprocess
            result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        iface = parts[1].strip().split('@')[0]
                        if iface and iface not in ['lo', 'sit0']:
                            interfaces.append(iface)
        except Exception:
            pass

    if not interfaces:
        interfaces = ["eth0", "wlan0", "ens33", "ens192", "enp0s3", "lo", "any"]

    return sorted(list(set(interfaces)))


class DNSMonitor:
    """
    Monitors DNS traffic in a lab environment.

    SAFETY: Only use in isolated VirtualBox Host-Only/Internal networks.
    This monitor passively listens for DNS traffic and feeds it to the
    detection engine. It does NOT perform any active attacks.
    """

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface
        self.is_running = False
        self.packet_count = 0
        self.callback: Optional[Callable] = None
        self._thread: Optional[threading.Thread] = None
        self._packet_buffer: List[Any] = []  # Buffer for batch processing
        self._batch_size = 100  # Process 100 packets at a time
        self._lock = threading.Lock()  # Thread safety for packet buffer

        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Live monitoring disabled. Install: pip install scapy")

    def set_callback(self, callback: Callable) -> None:
        """Set callback function for real-time processing."""
        self.callback = callback

    def _packet_handler(self, packet) -> None:
        """Handle a captured DNS packet with batching."""
        try:
            if not packet.haslayer(DNS):
                return

            if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                return

            # Extract IP info
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            dns_layer = packet[DNS]

            # Only process responses (QR bit = 1)
            if not dns_layer.qr:
                return

            # Extract domain from query section
            if not dns_layer.qd:
                return

            domain = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')

            # Extract response IP
            response_ip = None
            ttl = None
            query_type = "A"

            if dns_layer.an:
                rr = dns_layer.an[0]
                query_type = {1: "A", 28: "AAAA", 5: "CNAME"}.get(rr.type, "OTHER")

                if rr.type == 1:  # A record
                    try:
                        import socket
                        response_ip = socket.inet_ntoa(rr.rdata) if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    except Exception:
                        response_ip = str(rr.rdata)
                elif rr.type == 28:  # AAAA
                    try:
                        import socket
                        response_ip = socket.inet_ntop(socket.AF_INET6, rr.rdata) if isinstance(rr.rdata, bytes) else str(rr.rdata)
                    except Exception:
                        response_ip = str(rr.rdata)

                if hasattr(rr, 'ttl'):
                    ttl = rr.ttl

            # Add to buffer for batch processing
            with self._lock:
                self._packet_buffer.append({
                    'packet': packet,
                    'domain': domain,
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'dns_layer': dns_layer,
                    'response_ip': response_ip,
                    'ttl': ttl,
                    'query_type': query_type
                })
        except Exception as e:
            logger.error(f"Error handling packet: {e}")

    def _process_batch(self) -> None:
        """Process a batch of buffered packets."""
        if not self._packet_buffer:
            return

        with self._lock:
            packets_to_process = self._packet_buffer.copy()
            self._packet_buffer.clear()

        for item in packets_to_process:
            try:
                packet = item['packet']
                if not packet.haslayer(DNS):
                    continue

                if not packet.haslayer(IP) and not packet.haslayer(IPv6):
                    continue

                # Extract IP info
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                else:
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst

                dns_layer = item['dns_layer']

                # Only process responses (QR bit = 1)
                if not dns_layer.qr:
                    continue

                # Extract domain from query section
                if not dns_layer.qd:
                    continue

                domain = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')

                # Extract response IP
                response_ip = None
                ttl = None
                query_type = "A"

                if dns_layer.an:
                    rr = dns_layer.an[0]
                    query_type = {1: "A", 28: "AAAA", 5: "CNAME"}.get(rr.type, "OTHER")

                    if rr.type == 1:  # A record
                        try:
                            import socket
                            response_ip = socket.inet_ntoa(rr.rdata) if isinstance(rr.rdata, bytes) else str(rr.rdata)
                        except Exception:
                            response_ip = str(rr.rdata)
                    elif rr.type == 28:  # AAAA
                        try:
                            import socket
                            response_ip = socket.inet_ntop(socket.AF_INET6, rr.rdata) if isinstance(rr.rdata, bytes) else str(rr.rdata)
                        except Exception:
                            response_ip = str(rr.rdata)

                    if hasattr(rr, 'ttl'):
                        ttl = rr.ttl

                # Analyze through detection engine
                event = analyze_dns_event(
                    domain=domain,
                    source_ip=src_ip,
                    query_type=query_type,
                    response_ip=response_ip,
                    ttl=ttl,
                    dns_server=dst_ip,
                    is_simulation=False
                )

                self.packet_count += 1

                # Call callback if set
                if self.callback:
                    self.callback(event)

                logger.info(f"Captured DNS response: {domain} -> {response_ip} (Risk: {event.risk_score})")

            except Exception as e:
                logger.error(f"Error processing packet: {e}")

    def start(self, timeout: Optional[int] = None) -> None:
        """Start monitoring DNS traffic with optimized batching."""
        self.last_error = None
        if not SCAPY_AVAILABLE:
            self.last_error = "Scapy not installed. Live monitoring requires Scapy."
            logger.error(self.last_error)
            self.is_running = False
            return

        logger.warning(f"LAB MODE: Starting DNS monitor on interface '{self.interface or 'default'}'")
        self.is_running = True

        try:
            bpf_filter = "udp port 53 or tcp port 53"
            sniff_args = {
                "filter": bpf_filter,
                "prn": self._packet_handler,
                "store": False,
                "timeout": timeout,
                "stop_filter": lambda p: not self.is_running
            }
            if self.interface and self.interface.lower() != "any":
                sniff_args["iface"] = self.interface

            sniff(**sniff_args)
        except (PermissionError, OSError) as pe:
            self.last_error = f"Raw socket sniffing requires root/sudo privileges (e.g. sudo ./run.sh on Kali Linux). Details: {str(pe)}"
            logger.error(self.last_error)
        except Exception as e:
            self.last_error = f"Monitoring error: {str(e)}"
            logger.error(self.last_error)
        finally:
            self.is_running = False

    def start_async(self) -> None:
        """Start monitoring in a background thread with batch processing."""
        if self.is_running:
            logger.warning("Monitor is already running")
            return
        self._thread = threading.Thread(target=self.start, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self.is_running = False
        logger.info("DNS monitor stopped")

    def start_async_with_batch(self) -> None:
        """Start monitoring with batch processing enabled."""
        if self.is_running:
            logger.warning("Monitor is already running")
            return
        self._thread = threading.Thread(target=self.start_with_batch, daemon=True)
        self._thread.start()

    def start_with_batch(self) -> None:
        """Start monitoring with explicit batch processing."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start monitoring - scapy not available")
            return

        logger.warning(f"LAB MODE: Starting DNS monitor with batch processing on interface '{self.interface or 'default'}'")
        self.is_running = True

        try:
            # Optimize BPF filter for better performance
            bpf_filter = "udp port 53 or tcp port 53"
            sniff_args = {
                "filter": bpf_filter,
                "prn": self._packet_handler,
                "store": False,
                "timeout": None,
                "stop_filter": lambda p: not self.is_running
            }
            if self.interface and self.interface.lower() != "any":
                sniff_args["iface"] = self.interface

            sniff(**sniff_args)
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.is_running = False

    def get_recent_events(self, limit: int = 100) -> List:
        """Get recent DNS events from database."""
        from app.database.models import DNSEvent
        from sqlalchemy import desc

        with get_db_session() as db:
            return db.query(DNSEvent).order_by(desc(DNSEvent.timestamp)).limit(limit).all()

    def get_recent_events(self, limit: int = 100) -> List:
        """Get recent DNS events from database."""
        from app.database.models import DNSEvent
        from sqlalchemy import desc

        with get_db_session() as db:
            return db.query(DNSEvent).order_by(desc(DNSEvent.timestamp)).limit(limit).all()


# ============ Global Singleton Manager ============
_global_monitor: Optional[DNSMonitor] = None
_global_monitor_lock = threading.Lock()


def get_global_monitor() -> DNSMonitor:
    """Get or create the global DNS monitor instance."""
    global _global_monitor
    with _global_monitor_lock:
        if _global_monitor is None:
            _global_monitor = DNSMonitor()
        return _global_monitor


def start_global_monitor(interface: Optional[str] = None) -> Dict[str, Any]:
    """Start the global DNS monitor."""
    if not SCAPY_AVAILABLE:
        return {
            "running": False,
            "error": True,
            "message": "Scapy is not installed. Live network sniffing requires Scapy and root/sudo permissions (e.g. sudo ./run.sh on Kali Linux)."
        }

    monitor = get_global_monitor()
    if monitor.is_running:
        return {"running": True, "message": "Monitor already active", "interface": monitor.interface}

    monitor.interface = interface
    monitor.start_async()
    return {"running": True, "message": f"Started live monitoring on interface '{interface or 'default'}'", "interface": interface}


def stop_global_monitor() -> Dict[str, Any]:
    """Stop the global DNS monitor."""
    monitor = get_global_monitor()
    monitor.stop()
    return {"running": False, "message": "Monitor stopped"}


def get_monitor_status() -> Dict[str, Any]:
    """Get monitor status."""
    monitor = get_global_monitor()
    return {
        "running": monitor.is_running,
        "scapy_available": SCAPY_AVAILABLE,
        "interface": monitor.interface or "default",
        "packet_count": monitor.packet_count,
        "last_error": getattr(monitor, 'last_error', None),
        "available_interfaces": get_available_interfaces()
    }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("Available interfaces:", get_available_interfaces())