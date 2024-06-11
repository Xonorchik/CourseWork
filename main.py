import re
from scapy.all import IP, TCP, Raw, wrpcap
import sys


def split_and_convert(text):

    def is_hex_string(s):
        return all(c in '0123456789abcdefABCDEF ' for c in s)

    parts = text.split("|")

    def process_part(part):
        part = part.strip()
        if is_hex_string(part):
            return bytes.fromhex(part)
        return part.encode()

    converted_parts = list(map(process_part, filter(bool, parts)))
    converted_parts.append(b'')

    return converted_parts


def create_pld(segs):
    return b"".join(segs)


def send_cntnt(src_ip, src_port, dst_ip, dst_port, cntnt):
    ip_ = IP(src=str(src_ip), dst=str(dst_ip))
    tcp_ = TCP(sport=int(src_port), dport=int(dst_port), flags='PA')

    if cntnt:
        cntnt_convert = split_and_convert(cntnt)
        print(f"Content_convert: {cntnt_convert}")
        pld = create_pld(cntnt_convert)
        print(f"Payload: {pld}")
    else:
        print("Payload is empty")
        pld = b""

    packet = ip_ / tcp_ / Raw(load=pld)
    wrpcap("pcaps/file.pcap", packet)


def main():
    snort_rule = sys.stdin.readline()
    snort_rule = str(snort_rule)

    patterns = {
        'flow': r'flow:(.*?);',
        'content':
        r'content:"(.*?)";\s*(?:distance:(\d+);)?\s*(?:within:(\d+);)?',
        'cntnt': r'cntnt:"(.*?)";\s*(?:distance:(\d+);)?\s*(?:within:(\d+);)?',
        'reference': r'reference:(.*?);',
        'classtype': r'classtype:(.*?);',
        'sid': r'sid:(\d+);',
        'rev': r'rev:(\d+);',
        'metadata': r'metadata:(.*?);'
    }

    rule_head = re.split(r'\(.*\)', snort_rule)[0].strip()
    rule_parts = [
        part.strip() for part in rule_head.split(' ') if part != '->'
    ]

    action_field, prtcl, src_address, src_port, dst_address, dst_port = rule_parts

    def search_pattern(pattern, rule):
        match = re.search(pattern, rule)
        return match.group(1) if match else None

    flow = search_pattern(patterns['flow'], snort_rule)
    content_matches = re.findall(patterns['content'], snort_rule) + re.findall(
        patterns['cntnt'], snort_rule)
    contents = [m[0] for m in content_matches]
    distances = [m[1] if m[1] else "#" for m in content_matches]
    withins = [m[2] if m[2] else "#" for m in content_matches]

    reference = search_pattern(patterns['reference'], snort_rule)
    classtype = search_pattern(patterns['classtype'], snort_rule)
    sid = search_pattern(patterns['sid'], snort_rule)
    rev = search_pattern(patterns['rev'], snort_rule)
    metadata = search_pattern(patterns['metadata'], snort_rule)

    print(f"Action_Field: {action_field}")
    print(f"Protocol: {prtcl}")
    print(f"Source_address: {src_address}")
    print(f"Source_port: {src_port}")
    print(f"Destination_address: {dst_address}")
    print(f"Destination_port: {dst_port}")
    print(f"Flow: {flow}")
    print(f"Contents: {contents}")
    print(f"Distances: {distances}")
    print(f"Withins: {withins}")
    print(f"Reference: {reference}")
    print(f"Classtype: {classtype}")
    print(f"SID: {sid}")
    print(f"Rev: {rev}")
    print(f"Metadata: {metadata}")


    cntnt_end = ""
    character_flag = False

    for idx, word in enumerate(contents):
        if word.startswith('|') and word.endswith('|'):
            if idx == 0:
                cntnt_end += word[:-1]
            elif character_flag:
                character_flag = False
                if distances[idx].isdigit() and int(distances[idx]) >= 1:
                    cntnt_end += " aa" * int(distances[idx])
                cntnt_end += word[:-1]
            else:
                if distances[idx].isdigit() and int(distances[idx]) >= 1:
                    cntnt_end += " aa" * int(distances[idx])
                cntnt_end += " " + word[1:-1]
        else:
            if idx == 0:
                if word[-1] == "|":
                    cntnt_end += word[:-1]
                else:
                    cntnt_end += word
                    character_flag = True
            else:
                if distances[idx].isdigit() and int(distances[idx]) >= 1:
                    cntnt_end += " aa" * int(distances[idx])
                if word[0] != "|" and word[-1] != "|":
                    cntnt_end += " " + word
                    character_flag = True
                elif word[0] != "|" and word[-1] == "|":
                    cntnt_end += " " + word[:-1]
                else:
                    cntnt_end += " " + word[1:]
                character_flag = True
        if idx == len(contents) - 1 and word[-1] == "|":
            cntnt_end += "|"
            
    print(f"Content_end: {cntnt_end}")

    send_cntnt(src_address, src_port, dst_address, dst_port, cntnt_end)


main()
