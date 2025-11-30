#!/usr/bin/env python3
import json

flows = {}
total_packets = 0

with open('firewall_log.json', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            total_packets += 1
            
            # Create 5-tuple key
            key = (
                obj.get('src_ip', ''),
                obj.get('dst_ip', ''),
                obj.get('src_port', 0),
                obj.get('dst_port', 0),
                obj.get('proto', 0)
            )
            
            if key not in flows:
                flows[key] = 0
            flows[key] += 1
            
        except json.JSONDecodeError:
            continue

print(f"Total packets in log: {total_packets}")
print(f"Unique flows (5-tuple): {len(flows)}")
print(f"\nTop 10 flows by packet count:")
sorted_flows = sorted(flows.items(), key=lambda x: x[1], reverse=True)
for i, (key, count) in enumerate(sorted_flows[:10], 1):
    src_ip, dst_ip, src_port, dst_port, proto = key
    proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
    print(f"{i}. {src_ip}:{src_port} → {dst_ip}:{dst_port} ({proto_name}): {count} packets")
