import random
import time

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

counter_ = 1

def generate_random_ip():
    return ".".join(map(str, (random.randint(1, 254) for _ in range(4))))

def generate_random_port():
    return random.randint(1024, 65535)

def is_valid_ip(address):
    parts = address.split('.')
    if len(parts) != 4:
        return False
    return all(not (not part.isdigit() or not 0 <= int(part) <= 255) for part in parts)

def parse_rule_head(snort_rule):
    rule_head = snort_rule.split('(')[0].strip()
    rule_parts = [part.strip() for part in rule_head.split(' ') if part != '->']
    return rule_parts

def get_content_info(snort_rule):
    contents = []
    distances = []
    withins = []

    current_pos = 0
    while True:
        content_start = snort_rule.find('content:"', current_pos)
        cntnt_start = snort_rule.find('cntnt:"', current_pos)

        if content_start == -1 and cntnt_start == -1:
            break

        if cntnt_start == -1 or (content_start != -1 and content_start < cntnt_start):
            current_pos = content_start + 9
            end_quote = snort_rule.find('"', current_pos)
            contents.append(snort_rule[current_pos:end_quote])
            current_pos = end_quote + 1
        else:
            current_pos = cntnt_start + 7
            end_quote = snort_rule.find('"', current_pos)
            contents.append(snort_rule[current_pos:end_quote])
            current_pos = end_quote + 1

        distance_value = find_value('distance:', snort_rule[current_pos:])
        if distance_value:
            distances.append(distance_value)
        else:
            distances.append("#")

        within_value = find_value('within:', snort_rule[current_pos:])
        if within_value:
            withins.append(within_value)
        else:
            withins.append("#")

    while len(distances) < len(contents):
        distances.append("#")

    while len(withins) < len(contents):
        withins.append("#")

    return contents, distances, withins

def find_value(start_marker, rule):
    start_idx = rule.find(start_marker)
    if start_idx == -1:
        return None
    start_idx += len(start_marker)
    end_idx = rule.find(';', start_idx)
    return rule[start_idx:end_idx].strip() if end_idx != -1 else None

def parse_snort_conf(filename):
    ip_vars = {}
    port_vars = {}
    other_vars = []

    try:
        with open(filename, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if not line.startswith('#'):
                    if line.startswith('ipvar '):
                        parts = line.split()
                        var_name = parts[1]
                        var_value = parts[2]
                        ip_vars[var_name] = var_value
                    elif line.startswith('portvar '):
                        parts = line.split()
                        var_name = parts[1]
                        var_value = parts[2]
                        port_vars[var_name] = var_value
                    elif line.startswith('var '):
                        other_vars.append(line.split()[1])

    except FileNotFoundError:
        print(f"File '{filename}' not found.")

    return ip_vars, port_vars, other_vars

def choose_random_var(var_list):
    if isinstance(var_list, list):
        if var_list:
            return random.choice(var_list)
        else:
            return random.randint(1024, 65535)
    elif isinstance(var_list, int):
        return var_list
    else:
        print(f"Unexpected variable type: {type(var_list)}")
        return random.randint(1024, 65535)

def choose_random_ipvar(var_list):
    if isinstance(var_list, list):
        if var_list:
            return random.choice(var_list)
        else:
            return generate_random_ip()
    elif isinstance(var_list, int):
        return var_list
    else:
        print(f"Unexpected variable type: {type(var_list)}")
        return generate_random_ip()

def parse_snort_rule(snort_rule, ip_vars, port_vars):
    rule_parts = parse_rule_head(snort_rule)
    action_field, prtcl, src_address, src_port, dst_address, dst_port = rule_parts
    print("before port random", {dst_address})
    str_for_rplc = "any"
    if str(src_port).startswith("$") and src_port != 'any':
        src_port_value = port_vars.get(str(src_port).lstrip('$'), None)
        if src_port_value:
            src_port = choose_random_var(src_port_value)
        else:
            print(f"Variable {src_port} not found in portvar definitions. Replacing with 'any'.")
            src_port = str_for_rplc
    if str(dst_port).startswith("$") and dst_port != 'any':
        dst_port_value = port_vars.get(str(dst_port).lstrip('$'), None)
        if dst_port_value:
            dst_port = choose_random_var(dst_port_value)
        else:
            print(f"Variable {dst_port} not found in portvar definitions. Replacing with 'any'.")
            dst_port = str_for_rplc
            print("after rplc", {dst_port})
    if isinstance(ip_vars, dict):
        if str(src_address).startswith("$") and src_address != 'any':
            src_addr_value = ip_vars.get(str(src_address).lstrip('$'), None)
            if src_addr_value:
                src_address = choose_random_ipvar(src_addr_value)
            else:
                print(f"Variable {src_address} not found in portvar definitions. Replacing with 'any'.")
                src_address = str_for_rplc

        if str(dst_address).startswith("$") and dst_address != 'any':
            dst_addr_value = ip_vars.get(str(dst_address).lstrip('$'), None)
            if dst_addr_value:
                dst_address = choose_random_ipvar(dst_addr_value)
            else:
                print(f"Variable {dst_address} not found in portvar definitions. Replacing with 'any'.")
                dst_address = str_for_rplc
    else:
        print("Error: ip_vars is not a dictionary.")
    if src_address == 'any':
        src_address = generate_random_ip()
    elif isinstance(src_address, str) and src_address.startswith("["):
        array = src_address.strip("[]").split(",")
        if array[0].strip() == "any" and array[1].strip().startswith("!"):
            excluded_address = array[1].strip().lstrip("!")
            while True:
                new_address = generate_random_ip()
                if new_address != excluded_address:
                    src_address = new_address
                    break
        elif all("." in item for item in array):
            src_address = random.choice(array)
        else:
            print("Incorrect IP list format")
    elif isinstance(src_address, str) and src_address.startswith("[$"):
        var_name = src_address.lstrip('[').rstrip(']').split(',')[0].strip()
        if var_name.startswith('$'):
            src_address_value = port_vars.get(var_name.lstrip('$'), None)
            if src_address_value:
                src_address = choose_random_var(src_address_value)
            else:
                print(f"Variable {var_name} not found in portvar definitions.")
        else:
            print(f"Invalid variable format: {src_address}")
    if src_port == 'any':
        src_port = generate_random_port()
    elif isinstance(dst_port, str) and dst_port.startswith("[$"):
        var_name = dst_port.lstrip('[').rstrip(']').split(',')[0].strip()
        if var_name.startswith('$'):
            dst_port_value = port_vars.get(var_name.lstrip('$'), None)
            if dst_port_value:
                dst_port = choose_random_var(dst_port_value)
            else:
                print(f"Variable {var_name} not found in portvar definitions.")
        else:
            print(f"Invalid variable format: {dst_address}")
    if dst_address == 'any':
        dst_address = generate_random_ip()
    elif isinstance(dst_address, str) and dst_address.startswith("["):
        array = dst_address.strip("[]").split(",")
        if array[0].strip() == "any" and array[1].strip().startswith("!"):
            excluded_address = array[1].strip().lstrip("!")
            while True:
                new_address = generate_random_ip()
                if new_address != excluded_address:
                    dst_address = new_address
                    break
        else:
            print("Incorrect IP list format")
    elif isinstance(dst_address, str) and dst_address.startswith("[$"):
        var_name = dst_address.lstrip('[').rstrip(']').split(',')[0].strip()
        if var_name.startswith('$'):
            dst_address_value = port_vars.get(var_name.lstrip('$'), None)
            if dst_address_value:
                dst_address = choose_random_var(dst_address_value)
            else:
                print(f"Variable {var_name} not found in portvar definitions.")
        else:
            print(f"Invalid variable format: {dst_address}")

    if dst_port == 'any':
        dst_port = generate_random_port()
    elif isinstance(dst_port, str) and dst_port.startswith("[$"):
        var_name = dst_port.lstrip('[').rstrip(']').split(',')[0].strip()
        if var_name.startswith('$'):
            dst_port_value = port_vars.get(var_name.lstrip('$'), None)
            if dst_port_value:
                dst_port = choose_random_var(dst_port_value)
            else:
                print(f"Variable {var_name} not found in portvar definitions.")
        else:
            print(f"Invalid variable format: {dst_address}")
            
    def parse_port(port):
        if isinstance(port, str) and port.startswith("!$"):
            exclude_var = port[2:]
            include_ports = []
            
            for var_name, var_value in port_vars.items():
                if var_name == exclude_var:
                    if isinstance(var_value, list):
                        include_ports.extend(var_value)
                    else:
                        include_ports.append(var_value)
                    break

            if include_ports:
                while True:
                    random_port = random.randint(1024, 65535)
                    if random_port not in include_ports:
                        return random_port
            else:
                print(f"No ports available for variable {exclude_var}. Replacing with 'any'.")
                return str_for_rplc
        elif isinstance(port, str) and port.startswith("[") and not ":" in port and not "$" in port:
            port = eval(port)
            if port[0] > port[1]:
                min_port = port[1]
                max_port = port[0]
            else:
                min_port = port[0]
                max_port = port[1]
            random_port = random.randint(min_port, max_port)
            return random_port
        elif isinstance(port, str) and port.startswith("["):
            if port.startswith("["):
                parts = port[1:-1].split(",")
                parsed_ports = []
                for part in parts:
                    if ":" in part:
                        start_port, end_port = part.split(":")
                        start_port = int(start_port)
                        end_port = int(end_port)
                        random_port = random.randint(start_port, end_port)
                        parsed_ports.append(random_port)
                    elif "$" in part:
                        exclude_var = part[1:]
                        include_ports = []
                        for var_name, var_value in port_vars.items():
                            if var_name == exclude_var:
                                if isinstance(var_value, list):
                                    include_ports.extend(var_value)
                                else:
                                    include_ports.append(var_value)
                                break
                        if include_ports:
                            while True:
                                random_port = random.randint(1024, 65535)
                                if random_port not in include_ports:
                                    parsed_ports.append(random_port)
                                    break
                        else:
                            print(f"No ports available for variable {exclude_var}. Replacing with 'any'.")
                            parsed_ports.append(str_for_rplc)
                    else:
                        parsed_ports.append(int(part))
                return random.choice(parsed_ports)
            elif ":" in port:
                start_port, end_port = port.split(":")
                start_port = int(start_port)
                end_port = int(end_port)
                random_port = random.randint(start_port, end_port)
                return random_port
            elif port.isdigit():
                port = int(port)
                return port
        elif isinstance(port, int):
            return port
        elif isinstance(port, str) and ":" in port:
            if port.startswith("!"):
                start_port, end_port = port[1:].split(":")
            else:
                start_port, end_port = port.split(":")
            start_port = int(start_port) if start_port.isdigit() else 1024
            end_port = int(end_port) if end_port.isdigit() else 65535
            return random.randint(start_port, end_port)
        elif str(port).startswith("!"):
            while True:
                random_port = random.randint(1024, 65535)
                if random_port != int(port[1:]):
                    return random_port
        elif isinstance(port, str) and port.isdigit():
            return int(port)
        elif isinstance(port, int):
            return port
        else:
            print("Incorrect port format")
    src_port = parse_port(src_port)
    dst_port = parse_port(dst_port)
    
    contents, distances, withins = get_content_info(snort_rule)

    parsed_data = {
        'action_field': action_field,
        'protocol': prtcl,
        'src_address': src_address,
        'src_port': src_port,
        'dst_address': dst_address,
        'dst_port': dst_port,
        'contents': contents,
        'distances': distances,
        'withins': withins,
        'flow': find_value('flow:', snort_rule),
        'reference': find_value('reference:', snort_rule),
        'classtype': find_value('classtype:', snort_rule),
        'sid': find_value('sid:', snort_rule),
        'rev': find_value('rev:', snort_rule),
        'metadata': find_value('metadata:', snort_rule)
    }

    return parsed_data

def convert_parts_to_bytes(text):
    def is_hex_string(s):
        return all(c in '0123456789abcdefABCDEF ' for c in s)

    parts = text.split("|")
    converted_parts = []
    for part in parts:
        part = part.strip()
        if part and is_hex_string(part):
            try:
                converted_parts.append(bytes.fromhex(part.replace(" ", "")))
            except ValueError:
                converted_parts.append(part.encode())
        elif part:
            converted_parts.append(part.encode())

    return converted_parts

def create_pld(segs):
    return b"".join(segs)

def send_cntnt(src_ip, src_port, dst_ip, dst_port, cntnt):
    global counter_

    ip_ = IP(src=src_ip, dst=dst_ip)
    tcp_ = TCP(sport=int(src_port), dport=int(dst_port))
    if cntnt:
        cntnt_convert = convert_parts_to_bytes(cntnt)
        pld = create_pld(cntnt_convert)
    else:
        pld = b""

    packet = ip_ / tcp_ / Raw(load=pld)
    wrpcap(f"pcaps/file{str(counter_)}.pcap", packet)
    counter_ += 1

def main():
    filename = "snort.conf"
    with open("simple.rules.txt", "r") as file:
        ip_vars, port_vars, other_vars = parse_snort_conf(filename)
        for snort_rule in file:
            snort_rule = snort_rule.strip()
            if not snort_rule or snort_rule.startswith("#"):
                continue
            print(snort_rule)
            parsed_data = parse_snort_rule(snort_rule, ip_vars, port_vars)

            print(f"Action_Field: {parsed_data['action_field']}")
            print(f"Protocol: {parsed_data['protocol']}")
            print(f"Source_address: {parsed_data['src_address']}")
            print(f"Source_port: {parsed_data['src_port']}")
            print(f"Destination_address: {parsed_data['dst_address']}")
            print(f"Destination_port: {parsed_data['dst_port']}")
            print(f"Flow: {parsed_data['flow']}")
            print(f"Reference: {parsed_data['reference']}")
            print(f"Classtype: {parsed_data['classtype']}")
            print(f"SID: {parsed_data['sid']}")
            print(f"Rev: {parsed_data['rev']}")
            print(f"Metadata: {parsed_data['metadata']}")

            if parsed_data['contents']:
                print(f"Content: {parsed_data['contents']}")
            else:
                print("Content: []")

            if parsed_data['distances']:
                print(f"Distance: {parsed_data['distances']}")
            else:
                print("Distance: []")

            if parsed_data['withins']:
                print(f"Within: {parsed_data['withins']}")
            else:
                print("Within: []")

            if parsed_data['contents']:
                contend_result_parts = []
                for content in parsed_data['contents']:
                    if content.startswith('|') and content.endswith('|'):
                        contend_result_parts.append(content)
                    elif content.startswith('|'):
                        contend_result_parts.append(content + '|')
                    elif content.endswith('|'):
                        contend_result_parts.append('|' + content)
                    else:
                        contend_result_parts.append(content)
                contend_result = ''.join(contend_result_parts)
            else:
                contend_result = ""
            print(f"contend_result: {contend_result}")

            content_convert = convert_parts_to_bytes(contend_result)
            print(f"content_convert: {content_convert}")

            payload = create_pld(content_convert)
            print(f"payload: {payload}")

            send_cntnt(parsed_data['src_address'], parsed_data['src_port'],
                       parsed_data['dst_address'], parsed_data['dst_port'],
                       contend_result)
            print("*" * 50)
            time.sleep(0.1)

if __name__ == "__main__":
    main()
