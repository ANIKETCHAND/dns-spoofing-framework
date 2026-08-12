"""
DNS Packet Parser for PCAP Analysis.
Parses DNS queries and responses from packet capture files.
"""
import logging
from typing import List, Dict, Any, Optional, Generator
from dataclasses import dataclass
from datetime import datetime
import socket
import struct

# Try to import scapy for PCAP parsing
try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6, UDP, TCP, rdpcap
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    # Create dummy classes for type hints
    DNS = DNSQR = DNSRR = IP = IPv6 = UDP = TCP = PcapReader = object

logger = logging.getLogger(__name__)


@dataclass
class ParsedDNSRecord:
    """Parsed DNS record from a packet."""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    dns_server: str  # The server that responded (for responses)
    domain: str
    query_type: str
    query_type_num: int
    response_ip: Optional[str] = None
    response_ips: List[str] = None
    ttl: Optional[int] = None
    rcode: int = 0  # Response code
    is_response: bool = False
    raw_info: Dict[str, Any] = None

    def __post_init__(self):
        if self.response_ips is None:
            self.response_ips = []
        if self.raw_info is None:
            self.raw_info = {}


class DNSParser:
    """
    Parses DNS packets from PCAP files or live captures.
    Supports both IPv4 and IPv6, UDP and TCP.
    """

    # DNS Query Type mapping
    QTYPE_MAP = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }

    # DNS Response Code mapping
    RCODE_MAP = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }

    def __init__(self):
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. PCAP parsing will not work. Install with: pip install scapy")

    def parse_pcap(self, pcap_path: str) -> List[ParsedDNSRecord]:
        """
        Parse a PCAP file and extract DNS records.

        Args:
            pcap_path: Path to the PCAP file

        Returns:
            List of ParsedDNSRecord objects
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP parsing. Install with: pip install scapy")

        logger.info(f"Parsing PCAP file: {pcap_path}")

        try:
            # Use streaming parser for memory efficiency with large files
            packets = rdpcap(pcap_path)
        except Exception as e:
            logger.error(f"Failed to read PCAP file: {e}")
            raise

        records = []
        for packet in packets:
            try:
                record = self._parse_packet(packet)
                if record:
                    records.append(record)
            except Exception as e:
                logger.debug(f"Failed to parse packet: {e}")
                continue

        logger.info(f"Extracted {len(records)} DNS records from PCAP")
        return records

    def parse_pcap_streaming(self, pcap_path: str, batch_size: int = 1000) -> 'Generator[ParsedDNSRecord, None, None]':
        """
        Parse a PCAP file using streaming for memory efficiency.

        Args:
            pcap_path: Path to the PCAP file
            batch_size: Number of packets to process in each batch (for progress tracking)

        Yields:
            ParsedDNSRecord objects one at a time
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required for PCAP parsing. Install with: pip install scapy")

        logger.info(f"Streaming PCAP file: {pcap_path}")

        try:
            # Use PcapReader for streaming (memory efficient)
            from scapy.utils import PcapReader
            with PcapReader(pcap_path) as pcap_reader:
                packet_count = 0
                for packet in pcap_reader:
                    packet_count += 1
                    try:
                        record = self._parse_packet(packet)
                        if record:
                            yield record
                    except Exception as e:
                        logger.debug(f"Failed to parse packet: {e}")
                        continue

                    # Log progress periodically
                    if packet_count % batch_size == 0:
                        logger.debug(f"Processed {packet_count} packets...")

                logger.info(f"Streaming complete. Processed {packet_count} packets.")
        except Exception as e:
            logger.error(f"Failed to read PCAP file: {e}")
            raise

    def parse_pcap_chunked(self, pcap_path: str, chunk_size: int = 1000) -> List[List[ParsedDNSRecord]]:
        """
        Parse a PCAP file in chunks for batch processing.

        Args:
            pcap_path: Path to the PCAP file
            chunk_size: Number of records per chunk

        Returns:
            List of chunks, each containing up to chunk_size ParsedDNSRecord objects
        """
        chunks = []
        current_chunk = []

        for record in self.parse_pcap_streaming(pcap_path):
            current_chunk.append(record)
            if len(current_chunk) >= chunk_size:
                chunks.append(current_chunk)
                current_chunk = []

        if current_chunk:
            chunks.append(current_chunk)

        return chunks

    def _parse_packet(self, packet) -> Optional[ParsedDNSRecord]:
        """Parse a single packet for DNS data."""
        if not packet.haslayer(DNS):
            return None

        dns_layer = packet[DNS]

        # Get IP addresses
        src_ip = dst_ip = "Unknown"
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return None  # No IP layer

        # Determine if query or response
        is_response = bool(dns_layer.qr)  # QR bit: 0=query, 1=response

        # Parse query section
        domain = ""
        query_type = "UNKNOWN"
        query_type_num = 0

        if dns_layer.qd:
            qd = dns_layer.qd
            domain = qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            query_type_num = qd.qtype
            query_type = self.QTYPE_MAP.get(query_type_num, f"TYPE{query_type_num}")

        # Parse response section
        response_ip = None
        response_ips = []
        ttl = None

        if is_response and dns_layer.an:
            for i in range(dns_layer.ancount):
                rr = dns_layer.an[i]
                if rr.type == 1:  # A record
                    try:
                        ip = socket.inet_ntoa(rr.rdata)
                        response_ips.append(ip)
                        if response_ip is None:
                            response_ip = ip
                    except Exception:
                        pass
                elif rr.type == 28:  # AAAA record
                    try:
                        ip = socket.inet_ntop(socket.AF_INET6, rr.rdata)
                        response_ips.append(ip)
                        if response_ip is None:
                            response_ip = ip
                    except Exception:
                        pass
                elif rr.type == 5:  # CNAME
                    cname = rr.rdata.decode('utf-8', errors='ignore').rstrip('.')
                    response_ips.append(f"CNAME:{cname}")

                # Get TTL from first answer
                if ttl is None and hasattr(rr, 'ttl'):
                    ttl = rr.ttl

        # Determine DNS server (the responder for responses, destination for queries)
        dns_server = dst_ip if is_response else src_ip

        # Build raw info for storage
        raw_info = {
            "qr": dns_layer.qr,
            "opcode": dns_layer.opcode,
            "rcode": dns_layer.rcode,
            "rcode_name": self.RCODE_MAP.get(dns_layer.rcode, f"RCODE{dns_layer.rcode}"),
            "qdcount": dns_layer.qdcount,
            "ancount": dns_layer.ancount,
            "nscount": dns_layer.nscount,
            "arcount": dns_layer.arcount,
            "id": dns_layer.id,
        }

        return ParsedDNSRecord(
            timestamp=datetime.fromtimestamp(float(packet.time)),
            source_ip=src_ip,
            destination_ip=dst_ip,
            dns_server=dns_server,
            domain=domain,
            query_type=query_type,
            query_type_num=query_type_num,
            response_ip=response_ip,
            response_ips=response_ips,
            ttl=ttl,
            rcode=dns_layer.rcode,
            is_response=is_response,
            raw_info=raw_info
        )

    def parse_live_packet(self, packet) -> Optional[ParsedDNSRecord]:
        """Parse a live packet (same as _parse_packet but for live capture)."""
        return self._parse_packet(packet)


def extract_dns_from_pcap(pcap_path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to extract DNS data from PCAP as list of dicts.

    Args:
        pcap_path: Path to PCAP file

    Returns:
        List of dictionaries with DNS event data
    """
    parser = DNSParser()
    records = parser.parse_pcap(pcap_path)

    return [
        {
            "timestamp": r.timestamp.isoformat(),
            "source_ip": r.source_ip,
            "destination_ip": r.destination_ip,
            "dns_server": r.dns_server,
            "domain": r.domain,
            "query_type": r.query_type,
            "query_type_num": r.query_type_num,
            "response_ip": r.response_ip,
            "response_ips": r.response_ips,
            "ttl": r.ttl,
            "rcode": r.rcode,
            "rcode_name": r.raw_info.get("rcode_name", "UNKNOWN"),
            "is_response": r.is_response,
            "raw_info": r.raw_info,
        }
        for r in records
    ]


def extract_dns_from_pcap_streaming(pcap_path: str) -> Generator[Dict[str, Any], None, None]:
    """
    Streaming convenience function to extract DNS data from PCAP.

    Args:
        pcap_path: Path to PCAP file

    Yields:
        Dictionaries with DNS event data one at a time
    """
    parser = DNSParser()
    for record in parser.parse_pcap_streaming(pcap_path):
        yield {
            "timestamp": record.timestamp.isoformat(),
            "source_ip": record.source_ip,
            "destination_ip": record.destination_ip,
            "dns_server": record.dns_server,
            "domain": record.domain,
            "query_type": record.query_type,
            "query_type_num": record.query_type_num,
            "response_ip": record.response_ip,
            "response_ips": record.response_ips,
            "ttl": record.ttl,
            "rcode": record.rcode,
            "rcode_name": record.raw_info.get("rcode_name", "UNKNOWN"),
            "is_response": record.is_response,
            "raw_info": record.raw_info,
        }


# Test function
def test_parser():
    """Test the parser with a sample PCAP if available."""
    import os
    test_pcap = "test_dns.pcap"
    if os.path.exists(test_pcap):
        records = extract_dns_from_pcap(test_pcap)
        for r in records[:5]:
            print(r)
    else:
        print(f"Test PCAP not found: {test_pcap}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    test_parser()