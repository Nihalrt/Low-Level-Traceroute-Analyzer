Traceroute Analyzer (Traceroute.py)
====================================

Overview:
---------
Traceroute.py is a Python script designed to analyze network traceroute data captured in `.pcap` files. 
It determines the path taken by packets to reach a destination by analyzing the IP headers and matching
probe and response packets.

This script supports both Linux-style (UDP-based) and Windows-style (ICMP-based) traceroutes.

What the code does:
---------
- Identifies source and destination IP addresses.
- Extracts and lists intermediate routers (hop IPs) in order.
- Computes average RTT (Round Trip Time) and standard deviation for each hop.
- Reports fragmentation details.
- Automatically distinguishes between Group 1 (UDP-based) and Group 2 (ICMP-based) traceroutes.


How to Run:
-----------
1. Open a terminal.
2. Ensure you have Python 3 installed by running:
   python3 --version

3. Place your `.pcap` file (e.g., trace.pcap) in the same directory as `Traceroute.py`.

4. Run the script with the following command:
   python3 Traceroute.py trace.pcap

Output:
-------
The script will output:
- The source and destination IP addresses.
- The list of intermediate routers.
- The protocol values observed.
- Fragmentation information.
- RTT statistics (average and standard deviation) per hop.

Example Output:
---------------
The IP address of the source node: 192.168.100.17
The IP address of ultimate destination node: 8.8.8.8
The IP addresses of the intermediate destination nodes:
        router 1: 142.104.68.167
        router 2: 142.104.68.1
        ...
The avg RTT between 192.168.100.17 and 142.104.68.167 is: 11.366667 ms, the s.d. is: 0.206988 ms

Notes:
------
- This script does not support IPv6 packets.
- Ensure the input `.pcap` contains full packet captures (not truncated).

