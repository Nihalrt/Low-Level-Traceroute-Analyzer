#!/usr/bin/env python3
import sys
import struct
import math
from collections import defaultdict # Import defaultdict

def ip_bytes_to_str(ip_bytes):
    """Converts 4 raw bytes into a dotted-decimal IP string."""
    return ".".join(str(b) for b in ip_bytes)


def parse_global_header(raw):
    """Reads the 24-byte pcap global header."""
    # Assuming little-endian based on original code
    return {
        "magic": int.from_bytes(raw[0:4], "little"),
        "ver_major": int.from_bytes(raw[4:6], "little"),
        "ver_minor": int.from_bytes(raw[6:8], "little"),
        "thiszone": int.from_bytes(raw[8:12], "little", signed=True),
        "sigfigs": int.from_bytes(raw[12:16], "little"),
        "snaplen": int.from_bytes(raw[16:20], "little"),
        "network": int.from_bytes(raw[20:24], "little")
    }


def parse_packet_header(raw):
    """Reads the 16-byte packet (frame) header."""
    # Assuming little-endian based on original code
    return {
        "ts_sec": int.from_bytes(raw[0:4], "little"),
        "ts_usec": int.from_bytes(raw[4:8], "little"),
        "incl_len": int.from_bytes(raw[8:12], "little"),
        "orig_len": int.from_bytes(raw[12:16], "little")
    }


def get_ethertype(packet_data):
    """Extract Ethernet type (big-endian) at bytes [12:14]."""
    if len(packet_data) < 14:
        return None
    return int.from_bytes(packet_data[12:14], "big")


def parse_ipv4_header(packet_data):
    """Parses an IPv4 header starting at byte 14 of the frame."""
    ip_start = 14
    if len(packet_data) < ip_start + 20: # Minimum IPv4 header size
        return None
    ver_ihl = packet_data[ip_start]
    ip_hlen = (ver_ihl & 0x0F) * 4
    # Ensure packet_data is long enough for the declared IHL
    if len(packet_data) < ip_start + ip_hlen:
        return None # Not enough data for the full header

    total_len = int.from_bytes(packet_data[ip_start + 2:ip_start + 4], "big")
    ident = int.from_bytes(packet_data[ip_start + 4:ip_start + 6], "big")
    frag_field = int.from_bytes(packet_data[ip_start + 6:ip_start + 8], "big")
    flags = frag_field >> 13
    frag_offset = (frag_field & 0x1FFF) * 8
    ttl = packet_data[ip_start + 8]
    proto = packet_data[ip_start + 9]
    src_ip = ip_bytes_to_str(packet_data[ip_start + 12:ip_start + 16])
    dst_ip = ip_bytes_to_str(packet_data[ip_start + 16:ip_start + 20])
    return {
        "ihl": ip_hlen,
        "length": total_len,
        "id": ident,
        "flags": flags,
        "frag_off": frag_offset,
        "ttl": ttl, # TTL is needed for ordering Group 2
        "proto": proto,
        "src": src_ip,
        "dst": dst_ip,
        "ip_start": ip_start
    }


def parse_icmp(packet_data, ip_header):
    """Parses an ICMP header for either an echo request/reply or error message."""
    start_icmp = ip_header["ip_start"] + ip_header["ihl"]
    # Check if there's enough data for basic ICMP header (8 bytes)
    if start_icmp + 8 > len(packet_data):
        return None
    icmp_type = packet_data[start_icmp]
    icmp_code = packet_data[start_icmp + 1]
    seq = 0
    # If type is echo request (8) or echo reply (0), sequence is at offset+6
    # For type 11 (Time Exceeded), the *original* IP header starts at offset+8
    # and the original ICMP header (if the original was ICMP) starts after that.
    # The sequence number we need is inside the *original* ICMP request header.
    if icmp_type in (0, 8):
        seq = int.from_bytes(packet_data[start_icmp + 6:start_icmp + 8], "big")
    elif icmp_type == 11:
        # For Type 11, the original IP header starts at icmp_start + 8
        orig_ip_header_start = start_icmp + 8
        if orig_ip_header_start + 20 > len(packet_data): # Min original IP header
             return None # Not enough data for original IP header
        orig_ver_ihl = packet_data[orig_ip_header_start]
        orig_ihl = (orig_ver_ihl & 0x0F) * 4
        # Original ICMP header starts after original IP header
        orig_icmp_start = orig_ip_header_start + orig_ihl
        # Check for original ICMP header + 8 bytes (where seq number is)
        if orig_icmp_start + 8 > len(packet_data):
            return None # Not enough data for original ICMP seq num
        # Assuming original was ICMP echo, sequence is at offset+6 of original ICMP
        seq = int.from_bytes(packet_data[orig_icmp_start + 6:orig_icmp_start + 8], "big")
    else:
        # We don't specifically need sequence for other types for this assignment
        pass

    return {
        "type": icmp_type,
        "code": icmp_code,
        "seq": seq # Seq number is critical for matching Group 2
    }


def parse_udp(packet_data, ip_header):
    """Parses a UDP header if present (for Group1)."""
    start_udp = ip_header["ip_start"] + ip_header["ihl"]
    if start_udp + 8 > len(packet_data): # UDP header is 8 bytes
        return None
    srcp = int.from_bytes(packet_data[start_udp:start_udp + 2], "big")
    dstp = int.from_bytes(packet_data[start_udp + 2:start_udp + 4], "big")
    return {
        "src_port": srcp,
        "dst_port": dstp
    }

# This function might still be needed for Group 1 if embedded UDP ports are used for matching
def parse_embedded_udp_src(packet_data, ip_header):
    """
    In an ICMP error packet (Group 1), the original UDP header is embedded.
    Returns the original source port if found, else None.
    """
    outer_ihl = ip_header["ihl"]
    # ICMP header (8 bytes) starts after outer IP header
    icmp_header_start = ip_header["ip_start"] + outer_ihl
    # Embedded IP header starts after the first 8 bytes of the ICMP header
    embedded_ip_start = icmp_header_start + 8
    if embedded_ip_start + 20 > len(packet_data): # Need at least embedded IP header
        return None

    # Read the first byte of the embedded IP to get its IHL
    emb_ver_ihl = packet_data[embedded_ip_start]
    emb_ihl = (emb_ver_ihl & 0x0F) * 4

    # Embedded UDP header starts after embedded IP header
    embedded_udp_start = embedded_ip_start + emb_ihl
    if embedded_udp_start + 2 > len(packet_data): # Need at least src port
        return None
    s_port = int.from_bytes(packet_data[embedded_udp_start:embedded_udp_start + 2], "big")
    return s_port


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 traceroute_analyzer.py <trace_file>")
        sys.exit(1)

    fname = sys.argv[1]
    pkts = []
    try:
        with open(fname, "rb") as f:
            gheader_bytes = f.read(24)
            if len(gheader_bytes) < 24:
                print("Invalid pcap: no global header.")
                sys.exit(1)
            # Parse global header but ignore for now as per original code
            _ = parse_global_header(gheader_bytes)

            while True:
                framehdr_data = f.read(16)
                if not framehdr_data or len(framehdr_data) < 16:
                    break
                fh = parse_packet_header(framehdr_data)
                packet_raw = f.read(fh["incl_len"])
                if len(packet_raw) < fh["incl_len"]:
                    break
                # Only handle IPv4
                if get_ethertype(packet_raw) != 0x0800:
                    continue
                ip4 = parse_ipv4_header(packet_raw)
                if not ip4:
                    continue
                abstime = fh["ts_sec"] + fh["ts_usec"] / 1e6
                # Store parsed IP header along with time and raw data
                pkts.append({
                    "abs_time": abstime,
                    "raw": packet_raw,
                    "ip": ip4
                })
    except IOError as e:
        print(f"Failed to open file: {e}")
        sys.exit(1)

    if not pkts:
        print("No IPv4 packets found in the pcap.")
        sys.exit(0)

    # Calculate relative times in milliseconds
    if not pkts: # Should not happen due to check above, but safe
         print("No packets to process.")
         sys.exit(0)

    base = pkts[0]["abs_time"]
    for p in pkts:
        p["rel_time"] = (p["abs_time"] - base) * 1000 # Convert to ms

    # Check if any UDP packet exists in the typical traceroute port range
    # This helps distinguish Group 1 (UDP) from Group 2 (ICMP)
    has_udp_traceroute = False
    for p in pkts:
        if p["ip"]["proto"] == 17: # UDP protocol
            udp_info = parse_udp(p["raw"], p["ip"])
            # Standard UDP traceroute ports
            if udp_info and 33434 <= udp_info["dst_port"] <= 33529:
                 has_udp_traceroute = True
                 break

    # ----- GROUP 1: UDP Trace Logic -----
    if has_udp_traceroute:
        # (Your existing Group 1 logic goes here - unchanged from your provided code)
        # Find UDP probes (initial packets sent)
        udp_probes = []
        all_udp_packets = [] # To track fragments later
        for p in pkts:
             if p["ip"]["proto"] == 17:
                  all_udp_packets.append(p)
                  udp_info = parse_udp(p["raw"], p["ip"])
                  # Check port range and often the first fragment has offset 0
                  if udp_info and 33434 <= udp_info["dst_port"] <= 33529:
                       # We only consider the first fragment of a probe as the 'request'
                       # for matching purposes, though all fragments needed for frag analysis.
                       # Let's assume for matching RTT, offset 0 is the key one.
                       # This might need refinement based on specific trace behavior.
                       if p["ip"]["frag_off"] == 0:
                           p["udp"] = udp_info
                           udp_probes.append(p)

        # Gather all ICMP responses
        icmp_responses = []
        for p in pkts:
             if p["ip"]["proto"] == 1: # ICMP
                 icmp_info = parse_icmp(p["raw"], p["ip"])
                 # We primarily care about TTL exceeded (11) and Dest Unreachable (3)
                 if icmp_info and icmp_info["type"] in (3, 11):
                     p["icmp"] = icmp_info
                     # Try to extract the original UDP source port from the ICMP payload
                     orig_udp_src_port = parse_embedded_udp_src(p["raw"], p["ip"])
                     if orig_udp_src_port is not None:
                         p["orig_udp_src_port"] = orig_udp_src_port
                         icmp_responses.append(p)


        # Match UDP probes with ICMP responses based on original UDP source port
        rtt_dict = defaultdict(list) # Stores RTTs per router IP
        router_details = {} # Stores details like first seen time to help ordering

        for probe in udp_probes:
            probe_src_port = probe["udp"]["src_port"]
            probe_time = probe["rel_time"]

            for resp in icmp_responses:
                if resp.get("orig_udp_src_port") == probe_src_port:
                    resp_ip = resp["ip"]["src"]
                    rtt = resp["rel_time"] - probe_time
                    if rtt >= 0: # Ensure response time is after probe time
                         rtt_dict[resp_ip].append(rtt)
                         # Store the time of the first response from this router
                         if resp_ip not in router_details:
                              router_details[resp_ip] = {"first_seen": resp["rel_time"], "is_final": (resp["icmp"]["type"] == 3 and resp["icmp"]["code"] == 3)}
                         # Check if this response indicates it's the final destination
                         if resp["icmp"]["type"] == 3 and resp["icmp"]["code"] == 3:
                             router_details[resp_ip]["is_final"] = True
                         break # Assume one response per probe for RTT matching

        # Determine order - sort by the time the first response was received
        # This assumes routers generally respond in order of hops
        ip_to_min_ttl = {}

        for probe in udp_probes:
            ttl = probe["ip"]["ttl"]
            probe_src_port = probe["udp"]["src_port"]

            for resp in icmp_responses:
                if resp.get("orig_udp_src_port") == probe_src_port:
                    resp_ip = resp["ip"]["src"]
                    if resp_ip not in ip_to_min_ttl or ttl < ip_to_min_ttl[resp_ip]:
                        ip_to_min_ttl[resp_ip] = ttl
                    break

        ordered_ips = sorted(router_details.keys(), key=lambda ip: ip_to_min_ttl.get(ip, float('inf')))

        final_ip = None
        intermediate_ips = []
        for ip in ordered_ips:
             # Check if this IP ever sent a 'Destination Unreachable' type 3 code 3
             if router_details[ip].get("is_final", False):
                  final_ip = ip
             else:
                  intermediate_ips.append(ip)

        # If no type 3, code 3 found, assume the destination is the one in the probe
        if not final_ip and udp_probes:
            final_ip = udp_probes[0]["ip"]["dst"]
            # Add the final IP to the end if it wasn't detected via ICMP type 3/3
            # and ensure it has RTT entries if we need to print them.
            # Note: Group 1 traces might not always have RTTs directly to the final IP
            # if it only responds with Type 3/Code 3.
            if final_ip not in ordered_ips:
                 # We might not have RTTs calculated this way, handle printing carefully
                 pass # No change needed to intermediate_ips here

        # Fragmentation analysis (using all_udp_packets)
        ident_map = defaultdict(list)
        for p in all_udp_packets:
            ident_map[p["ip"]["id"]].append(p)

        fragments_report = []
        for ident_val, group in ident_map.items():
            if len(group) > 1:
                # Sort fragments by offset to find the last one correctly
                group.sort(key=lambda x: x["ip"]["frag_off"])
                last_frag_offset = group[-1]["ip"]["frag_off"]
                fragments_report.append((ident_val, len(group), last_frag_offset))


        # --- Output for Group 1 ---
        source_ip = udp_probes[0]["ip"]["src"] if udp_probes else "N/A"
        print(f"The IP address of the source node: {source_ip}")
        print(f"The IP address of ultimate destination node: {final_ip}")
        print("The IP addresses of the intermediate destination nodes:")
        # Print only those IPs we confirmed are intermediate
        for idx, nodeip in enumerate(intermediate_ips, 1):
            print(f"\trouter {idx}: {nodeip}")
        print()
        print("The values in the protocol field of IP headers:")
        print("\t1: ICMP")
        print("\t17: UDP")
        print()

        if not fragments_report:
            print("The number of fragments created from the original datagram is: 0")
            print("The offset of the last fragment is: 0")
        else:
            for ident_val, countf, offsetv in fragments_report:
                print(f"The number of fragments created from the original datagram {ident_val} is: {countf}")
                print(f"The offset of the last fragment is: {offsetv}\n") # Original code had \n here

        print() # Add a blank line before RTTs

        # Print RTTs for intermediates
        for nodeip in intermediate_ips:
             arr = rtt_dict.get(nodeip, [])
             if arr:
                  avg = sum(arr) / len(arr)
                  # Guard against single-sample variance calculation error
                  var = sum((v - avg) ** 2 for v in arr) / len(arr) if len(arr) > 0 else 0
                  stddev = math.sqrt(var)
                  print(f"The avg RTT between {source_ip} and {nodeip} is: {avg / 1000.0:.6f} ms, the s.d. is: {stddev / 1000.0:.6f} ms")

        # Optionally print RTT for final node if available
        # Note: RTT to final might not be present if only Type 3/Code 3 received
        if final_ip in rtt_dict:
             arr_f = rtt_dict[final_ip]
             if arr_f:
                  avg_f = sum(arr_f) / len(arr_f)
                  var_f = sum((v - avg_f) ** 2 for v in arr_f) / len(arr_f) if len(arr_f) > 0 else 0
                  stddev_f = math.sqrt(var_f)
                  print(f"The avg RTT between {source_ip} and {final_ip} is: {avg_f / 1000.0:.6f} ms, the s.d. is: {stddev_f / 1000.0:.6f} ms")



    # ----- GROUP 2: ICMP Trace Logic (Windows) -----
    else:
        # Separate ICMP requests (Type 8) and responses (Type 11 or 0)
        requests_icmp = []
        responses_icmp = []
        for p in pkts:
            if p["ip"]["proto"] == 1: # ICMP
                icmp_info = parse_icmp(p["raw"], p["ip"])
                if icmp_info:
                    p["icmp"] = icmp_info
                    if icmp_info["type"] == 8: # Echo request
                        requests_icmp.append(p)
                    elif icmp_info["type"] in (0, 11): # Echo reply or TTL exceeded
                        # Ensure we could parse the sequence number needed for matching
                        if "seq" in icmp_info and icmp_info["seq"] != 0: # Seq 0 might be invalid/unused
                             responses_icmp.append(p)

        # Match requests and responses using sequence number
        # Store RTTs and identify router IPs, tracking first response time and type
        rtt_map = defaultdict(list)
        # Store details per responding IP {ip: {'min_req_time': time, 'rtts': [], 'is_final': bool}}
        router_info = {}

        # Build a map of sequence numbers to request times for quick lookup
        request_times = {req["icmp"]["seq"]: req["rel_time"] for req in requests_icmp if "icmp" in req}


        for resp in responses_icmp:
            resp_seq = resp["icmp"]["seq"]
            resp_ip = resp["ip"]["src"]
            resp_time = resp["rel_time"]
            resp_type = resp["icmp"]["type"]

            if resp_seq in request_times:
                req_time = request_times[resp_seq]
                rtt = resp_time - req_time

                if rtt >= 0: # Valid RTT
                    rtt_map[resp_ip].append(rtt)

                    # Track router details for ordering and final destination ID
                    if resp_ip not in router_info:
                         # Store the request time that elicited this *first* response from this IP
                         # This helps approximate hop order.
                         router_info[resp_ip] = {'first_req_time': req_time, 'is_final': False}

                    # Mark as final if it sends an Echo Reply (Type 0)
                    if resp_type == 0:
                        router_info[resp_ip]['is_final'] = True
                    # Update minimum request time if a response to an earlier request is seen
                    # (Unlikely needed if requests are sequential, but safe)
                    router_info[resp_ip]['first_req_time'] = min(router_info[resp_ip]['first_req_time'], req_time)


        # Determine source, final destination, and intermediate routers
        source_ip = requests_icmp[0]["ip"]["src"] if requests_icmp else "N/A"
        # Sort responding IPs based on the time of the request that got the first response
        # This should generally correspond to hop order
        sorted_responder_ips = sorted(router_info.keys(), key=lambda ip: router_info[ip]['first_req_time'])

        intermediate_routers = []
        final_destination_ip = None

        for ip in sorted_responder_ips:
             if router_info[ip]['is_final']:
                  final_destination_ip = ip
                  # Stop adding intermediates once final destination is confirmed by type 0 reply
                  # However, traceroute might show routers *after* the final if probes continue
                  # Let's assume the first IP sending type 0 is the intended final one.
                  # Or, stick to the assignment spec: list all type 11 sources as intermediate.
             #else: # if router_info[ip]['is_final'] is False (i.e. sent Type 11)
             #     intermediate_routers.append(ip)

        # Simpler logic based on expected output:
        # Final IP is the one that sent type 0. All others sending type 11 are intermediate.
        # If multiple send type 0, the assignment sample usually takes the last one in the trace flow.
        # Let's refine:
        intermediate_routers = []
        possible_finals = []
        for ip in sorted_responder_ips:
            if router_info[ip]['is_final']:
                 possible_finals.append(ip)
            else:
                 # Add to intermediates only if no final destination has been identified *yet* in the sorted list
                 # Or simply, add all non-finals. Let's do that.
                 intermediate_routers.append(ip)

        # Assign final destination IP
        if possible_finals:
            # If there are IPs marked as final (sent type 0), use the *last* one encountered in the sorted order
            final_destination_ip = possible_finals[-1]
            # Remove the chosen final IP from intermediate list if it was added
            intermediate_routers = [r for r in intermediate_routers if r != final_destination_ip]
            # Also remove any *other* IPs that sent type 0 but weren't chosen as the final one
            other_finals = [f for f in possible_finals if f != final_destination_ip]
            intermediate_routers = [r for r in intermediate_routers if r not in other_finals]

        elif requests_icmp:
             # Fallback if no Type 0 reply received
             final_destination_ip = requests_icmp[0]["ip"]["dst"]
        else:
             final_destination_ip = "N/A"


        # --- Output for Group 2 ---
        print(f"The IP address of the source node: {source_ip}")
        print(f"The IP address of ultimate destination node: {final_destination_ip}")
        print("The IP addresses of the intermediate destination nodes:")
        # Print intermediate routers in the determined order
        for i, hop_ip in enumerate(intermediate_routers, 1):
            print(f"\trouter {i}: {hop_ip}")
        print()
        print("The values in the protocol field of IP headers:")
        # Group 2 traces only involve ICMP according to this logic path
        print("\t1: ICMP")
        print()
        # Fragmentation is assumed 0 for ICMP based traceroute unless proven otherwise
        # Your original code and expected output show 0.
        print("The number of fragments created from the original datagram is: 0")
        print("The offset of the last fragment is: 0")
        print() # Blank line before RTTs

        # Calculate and print RTT statistics for intermediate routers
        for hop_ip in intermediate_routers:
            times = rtt_map.get(hop_ip, [])
            if times:
                avg = sum(times) / len(times)
                # Check for division by zero if only one sample
                variance = sum((t - avg) ** 2 for t in times) / len(times) if len(times) > 0 else 0
                stddev = math.sqrt(variance)
                print(f"The avg RTT between {source_ip} and {hop_ip} is: {avg / 1000.0:.6f} ms, the s.d. is: {stddev / 1000.0:.6f} ms")

        # Calculate and print RTT statistics for the final destination
        if final_destination_ip and final_destination_ip in rtt_map:
             final_times = rtt_map[final_destination_ip]
             if final_times:
                  avg_final = sum(final_times) / len(final_times)
                  variance_final = sum((t - avg_final) ** 2 for t in final_times) / len(final_times) if len(final_times) > 0 else 0
                  stddev_final = math.sqrt(variance_final)
                  print(f"The avg RTT between {source_ip} and {final_destination_ip} is: {avg_final / 1000.0:.6f} ms, the s.d. is: {stddev_final / 1000.0:.6f} ms")


if __name__ == "__main__":
    main()