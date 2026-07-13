import json
import re
import random
import os
import string

def generate_random_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )

def mutate_trace(trace_str: str) -> str:
    """
    Takes a raw JSONL string of a trace and mutates IPs, MACs, and common OS names
    to create a synthetic variant without breaking any JSON escaping.
    """
    mutated = trace_str
    
    # 1. Mutate IPv4 Addresses
    # Find all IPv4 addresses
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    found_ips = list(set(re.findall(ip_pattern, mutated)))
    
    # Generate a new random subnet base (e.g., 10.x.y. or 172.x.y. or 192.168.x.)
    subnet_type = random.choice(['10', '172', '192'])
    if subnet_type == '10':
        base = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}."
    elif subnet_type == '172':
        base = f"172.{random.randint(16, 31)}.{random.randint(0, 255)}."
    else:
        base = f"192.168.{random.randint(0, 255)}."
    
    # Map old IPs to new IPs
    ip_mapping = {}
    for ip in found_ips:
        # Don't mutate loopback or broadcast usually, but for LANCE simulation it's fine.
        if ip == '127.0.0.1' or ip == '0.0.0.0':
            continue
        # Preserve the host part (last octet) if possible to keep logic intact
        last_octet = ip.split('.')[-1]
        ip_mapping[ip] = f"{base}{last_octet}"
    
    # Apply IP mapping (sort by length descending to avoid partial matches)
    for old_ip in sorted(ip_mapping.keys(), key=len, reverse=True):
        mutated = mutated.replace(old_ip, ip_mapping[old_ip])
        
    # 2. Mutate MAC Addresses
    mac_pattern = r'\b(?:[0-9A-Fa-f]{2}[:-]){5}(?:[0-9A-Fa-f]{2})\b'
    found_macs = list(set(re.findall(mac_pattern, mutated)))
    mac_mapping = {mac: generate_random_mac() for mac in found_macs}
    for old_mac in sorted(mac_mapping.keys(), key=len, reverse=True):
        mutated = mutated.replace(old_mac, mac_mapping[old_mac])
        
    # 3. Mutate Device Names (e.g. s1-router -> s2-fw)
    # This adds some variety to hostnames and node IDs
    prefixes = ['s1-', 'v1-', 'gw-', 'rt-', 'fw-', 'edge-']
    new_prefix = random.choice(['alpha-', 'beta-', 'core-', 'dmz-', 'prod-', 'test-'])
    for prefix in prefixes:
        mutated = mutated.replace(prefix, new_prefix)
        
    # 4. Mutate some OS names for flavor
    os_swaps = {
        "Ubuntu": random.choice(["Debian", "CentOS", "Ubuntu", "Fedora"]),
        "Alpine": random.choice(["Alpine", "BusyBox", "TinyCore"]),
        "pfSense": random.choice(["pfSense", "OPNsense", "VyOS", "OpenWrt"])
    }
    for old_os, new_os in os_swaps.items():
        mutated = mutated.replace(f'"{old_os}"', f'"{new_os}"')
        
    # 5. Mutate Passwords (very basic replacement of known passwords)
    passwords = ['P@ssw0rd123', 'M@n@geM3nt2026!', 'superSecret!', 'W1reGu@rd!2026', 'admin', 'root']
    new_pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10)) + "!"
    
    # Only replace strong passwords to avoid breaking commands like "admin" user
    for pwd in ['P@ssw0rd123', 'M@n@geM3nt2026!', 'superSecret!', 'W1reGu@rd!2026']:
        mutated = mutated.replace(pwd, new_pwd)
        
    return mutated

def main():
    input_file = 'data/finetuning/dataset.jsonl'
    output_file = 'data/finetuning/dataset_mutated.jsonl'
    
    # We will mutate the top 5 traces identified earlier
    # 1-indexed lines: 1, 37, 38, 39, 40
    # 0-indexed indices: 0, 36, 37, 38, 39
    target_indices = [0, 36, 37, 38, 39]
    mutations_per_trace = 10  # Generate 10 variants per trace
    
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    print(f"Loaded {len(lines)} traces from {input_file}")
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    mutated_count = 0
    with open(output_file, 'w', encoding='utf-8') as out_f:
        for idx in target_indices:
            if idx >= len(lines):
                continue
                
            original_trace = lines[idx].strip()
            if not original_trace:
                continue
                
            print(f"Mutating trace {idx+1} ({mutations_per_trace} times)...")
            for m in range(mutations_per_trace):
                variant = mutate_trace(original_trace)
                out_f.write(variant + "\n")
                mutated_count += 1
                
    print(f"\nSuccess! Generated {mutated_count} new synthetic traces.")
    print(f"They are safely saved in: {output_file}")
    print(f"Your original dataset.jsonl was NOT modified.")

if __name__ == "__main__":
    main()
