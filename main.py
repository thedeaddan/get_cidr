from flask import Flask, render_template, request, session, send_file, redirect, url_for
import ipaddress, socket, subprocess, re, tempfile, os
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'your-super-secret-key'
app.permanent_session_lifetime = timedelta(hours=1)

TEMP_BAT_PATH = "generated_routes.bat"

def cidr_to_netmask(cidr: str):
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)

def resolve_domain(domain: str):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

def get_cidrs_from_whois(ip: str):
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        match = re.search(r'^CIDR:\s*(.+)', result.stdout, re.MULTILINE)
        if match:
            return [x.strip() for x in match.group(1).split(',')]
    except:
        pass
    return []

def generate_route_data(input_list):
    route_data = []
    errors = []
    seen = set()
    domain_count = 0

    for item in input_list:
        item = item.strip()
        if not item:
            continue
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', item):
            domain_count += 1
            ip = resolve_domain(item)
            if not ip:
                errors.append(f"{item} → ❌ DNS ошибка")
                continue
            cidrs = get_cidrs_from_whois(ip)
            if not cidrs:
                errors.append(f"{item} → {ip} → ❌ CIDR не найден")
                continue
            for cidr in cidrs:
                try:
                    network, netmask = cidr_to_netmask(cidr)
                    route = f'route add {network} mask {netmask} 0.0.0.0'
                    if route not in seen:
                        seen.add(route)
                        route_data.append((item, ip, cidr, route))
                except:
                    errors.append(f"{item} → {cidr} → ❌ ошибка")
        else:
            try:
                if '/' in item:
                    network, netmask = cidr_to_netmask(item)
                else:
                    ip = ipaddress.ip_address(item)
                    network, netmask = str(ip), '255.255.255.255'
                route = f'route add {network} mask {netmask} 0.0.0.0'
                if route not in seen:
                    seen.add(route)
                    route_data.append((item, str(ip), f"{network}/{ipaddress.IPv4Network(network + '/' + netmask).prefixlen}", route))
            except:
                errors.append(f"{item} → ❌ ошибка IP")

    return route_data, errors, domain_count

@app.route("/", methods=["GET", "POST"])
def index():
    route_data, errors, summary, history = [], [], {}, session.get("history", [])

    if request.method == "POST":
        raw_input = request.form.get("input_data", "")
        inputs = raw_input.strip().splitlines()
        route_data, errors, domain_count = generate_route_data(inputs)
        commands = [cmd for _, _, _, cmd in route_data]

        # сохранить .bat
        with open(TEMP_BAT_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(commands))

        # сохранить историю
        history_entry = {"count": len(commands), "input": inputs}
        history.insert(0, history_entry)
        session["history"] = history[:10]  # последние 10

        summary = {
            "total": len(commands),
            "unique_ips": len(set(x[1] for x in route_data)),
            "domains": domain_count,
        }

    return render_template("index.html", route_data=route_data, errors=errors, summary=summary, history=session.get("history", []))

@app.route("/download")
def download():
    if os.path.exists(TEMP_BAT_PATH):
        return send_file(TEMP_BAT_PATH, as_attachment=True, download_name="routes.bat")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=2022)
