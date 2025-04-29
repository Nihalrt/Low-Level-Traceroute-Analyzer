# PCAP Traceroute Analyzer

A Python-based tool that manually parses raw `.pcap` files to reconstruct traceroutes, identify intermediate hops, calculate round-trip times (RTTs), and detect IP fragmentation without relying on external libraries like Scapy or dpkt.

---

## Features

- Parses PCAP files manually to extract Ethernet, IPv4, UDP, and ICMP headers.
- Distinguishes between UDP-based traceroutes (Linux) and ICMP-based traceroutes (Windows).
- Identifies:
  - Source IP
  - Destination IP
  - Intermediate routers
- Calculates and displays:
  - Average RTT (Round Trip Time) per hop
  - Standard deviation of RTT
- Detects and reports IP packet fragmentation.
- Handles malformed packets and edge cases gracefully.

---

## Project Structure

```bash
Traceroute.py   # Main Python script
```

---

## Usage

### Requirements
- Python 3.x

No external libraries are needed.

### Running the Script

```bash
python3 Traceroute.py <trace_file.pcap>
```

- Replace `<trace_file.pcap>` with the path to your PCAP capture file.

### Example

```bash
python3 Traceroute.py sample_trace.pcap
```

---

## Output

- IP address of the source node
- IP address of the ultimate destination node
- IP addresses of intermediate routers
- Protocols involved
- Fragmentation details
- Average RTTs and standard deviations for each hop

---

## Highlights

- **Manual Parsing:** No third-party packet parsing libraries.
- **Low-Level Networking:** Deep dive into network packet structures.
- **Comprehensive Analysis:** Covers both UDP and ICMP-based traceroutes.

---

## License

This project is licensed under the MIT License.

---

## Author

**Sai Nihal Diddi**

- GitHub: [Nihalrt](https://github.com/Nihalrt)
- LinkedIn: [Sai Nihal Diddi](https://www.linkedin.com/in/sai-nihal-diddi-2444471bb/)

---

## Acknowledgments

- Inspired by manual packet decoding techniques.
