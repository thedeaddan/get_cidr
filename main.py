from flask import Flask, render_template, request
import ipaddress
import socket
import subprocess
import re

app = Flask(__name__)

def cidr_to_netmask(cidr: str) -> tuple[str, str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)

def resolve_domain(domain: str) -> str | None:
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except:
        return None

def get_cidrs_from_whois(ip: str) -> list[str]:
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        cidr_line = re.search(r'^CIDR:\s*(.+)', result.stdout, re.MULTILINE)
        if cidr_line:
            return [x.strip() for x in cidr_line.group(1).split(',')]
    except:
        pass
    return []

def generate_route_data(input_list: list[str]):
    route_data = []
    errors = []
    seen_routes = set()
    domain_count = 0

    for item in input_list:
        item = item.strip()
        if not item:
            continue

        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', item):  # domain
            domain_count += 1
            ip = resolve_domain(item)
            if not ip:
                errors.append(f"{item} → ❌ не удалось разрешить")
                continue
            cidrs = get_cidrs_from_whois(ip)
            if not cidrs:
                errors.append(f"{item} → {ip} → ⚠️ CIDR не найден")
                continue
            for cidr in cidrs:
                try:
                    network, netmask = cidr_to_netmask(cidr)
                    route = f'route add {network} mask {netmask} 0.0.0.0'
                    if route not in seen_routes:
                        seen_routes.add(route)
                        route_data.append((item, ip, cidr, route))
                except:
                    errors.append(f"{item} → {cidr} → ❌ ошибка обработки")
        else:
            try:
                if '/' in item:
                    network, netmask = cidr_to_netmask(item)
                else:
                    ip = ipaddress.ip_address(item)
                    network, netmask = str(ip), '255.255.255.255'
                route = f'route add {network} mask {netmask} 0.0.0.0'
                if route not in seen_routes:
                    seen_routes.add(route)
                    route_data.append((item, str(ip), f"{network}/{ipaddress.IPv4Network(network + '/' + netmask).prefixlen}", route))
            except:
                errors.append(f"{item} → ❌ ошибка IP/подсети")

    return route_data, errors, domain_count

@app.route("/", methods=["GET", "POST"])
def index():
    route_data = []
    errors = []
    domain_count = 0
    summary = {}

    if request.method == "POST":
        raw_input = request.form.get("input_data", "")
        inputs = raw_input.strip().splitlines()
        route_data, errors, domain_count = generate_route_data(inputs)

        summary = {
            "total": len(route_data),
            "unique_ips": len(set(x[1] for x in route_data)),
            "domains": domain_count,
        }

    return render_template("index.html", route_data=route_data, errors=errors, summary=summary)

if __name__ == "__main__":
    app.run(debug=True,host="0.0.0.0",port=2022)
