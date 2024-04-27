import sys

tcp_port_groups = {}
udp_port_groups = {}

def extract_rule_header(string: str):
    start = string.find('->')
    first_part = string[0:start-1].split(' ')
    proto = first_part[1]
    src_port = first_part[3]

    end = string.find('(')
    second_part = string[start+3:end-1].split(' ')
    dst_port = second_part[1]

    return proto, src_port, dst_port

def extrair_opcoes_content(string:str):
    inicio_content = string.find("content:")
    if inicio_content == -1:
        return
    opcoes_content = []
    fast_pattern = None
    while inicio_content != -1:
        inicio_valor = string.find('"', inicio_content) + 1
        fim_valor = string.find('"', inicio_valor)
        opcao_content = string[inicio_valor:fim_valor]
        fim_content = string.find(";", fim_valor)
        if "fast_pattern" in string[fim_valor:fim_content]:
            fast_pattern = opcao_content
        else:
            opcoes_content.append(opcao_content)
        inicio_content = string.find("content:", fim_valor)
    
    if not fast_pattern:
        fast_pattern = max(opcoes_content, key=len)
        opcoes_content.remove(fast_pattern)
    sid_inicio = string.find("sid:") + 4
    sid_fim = string.find(';', sid_inicio)
    return fast_pattern, opcoes_content, string[sid_inicio:sid_fim]

if __name__ == "__main__":
    file = open(sys.argv[1], "r")
    tcp_fp_with_sid_file = open("tcp-fp_with_sid.txt", "w")
    udp_fp_with_sid_file = open("udp-fp_with_sid.txt", "w")

    tcp_src_port_any = []
    tcp_dst_port_any = []
    udp_src_port_any = []
    udp_dst_port_any = []

    for line in file:
        if line and line.startswith('alert'):
            protocol, src, dst = extract_rule_header(line)
            fast_pattern, patterns, sid = extrair_opcoes_content(line)
            if protocol == "tcp":
                if src == "any":
                    tcp_src_port_any.append((src,dst))
                if dst == "any":
                    tcp_dst_port_any.append((src,dst))
                if tcp_port_groups.get((src,dst)) == None:
                    tcp_port_groups[(src,dst)] = ""
                if len(patterns) == 0:
                    tcp_port_groups[(src,dst)] += f"~{fast_pattern};{sid}"
                else:
                    tcp_port_groups[(src,dst)] += f"~{fast_pattern};{sid};"
                for p in patterns:
                    if p != patterns[-1]:  # não é o último
                        tcp_port_groups[(src,dst)] += f"{p},"
                    else:
                        tcp_port_groups[(src,dst)] += f"{p}"
            elif protocol == "udp":
                if src == "any":
                    udp_src_port_any.append((src,dst))
                if dst == "any":
                    udp_dst_port_any.append((src,dst))
                if udp_port_groups.get((src,dst)) == None:
                    udp_port_groups[(src,dst)] = ""
                if len(patterns) == 0:
                    udp_port_groups[(src,dst)] += f"~{fast_pattern};{sid}"
                else:
                    udp_port_groups[(src,dst)] += f"~{fast_pattern};{sid};"
                for p in patterns:
                    if p != patterns[-1]:  # não é o último
                        udp_port_groups[(src,dst)] += f"{p},"
                    else:
                        udp_port_groups[(src,dst)] += f"{p}"
            
    file.close()
  
    for pair in tcp_src_port_any:
        for key in tcp_port_groups:
            if key[0] != "any" and key[1] == pair[1]:
                tcp_port_groups[key] += tcp_port_groups[pair]

    for pair in tcp_dst_port_any:
        for key in tcp_port_groups:
            if key[0] == pair[0] and key[1] != "any":
                tcp_port_groups[key] += tcp_port_groups[pair]

    for pair in udp_src_port_any:
        for key in udp_port_groups:
            if key[0] != "any" and key[1] == pair[1]:
                udp_port_groups[key] += udp_port_groups[pair]

    for pair in udp_dst_port_any:
        for key in tcp_port_groups:
            if key[0] == pair[0] and key[1] != "any":
                udp_port_groups[key] += udp_port_groups[pair]

    # for x in tcp_port_groups:
    #     print(f"{x}: {tcp_port_groups[x]}")

    # for x in udp_port_groups:
    #     print(f"{x}: {udp_port_groups[x]}")


    for x in tcp_port_groups:
        tcp_fp_with_sid_file.write(f"{x[0]};{x[1]}{tcp_port_groups[x]}\n")

    for x in udp_port_groups:
        udp_fp_with_sid_file.write(f"{x[0]};{x[1]}{udp_port_groups[x]}\n")


    tcp_fp_with_sid_file.close()
    udp_fp_with_sid_file.close()
