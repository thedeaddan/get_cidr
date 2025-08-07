"""
Основной модуль Flask-приложения.
Получает на вход IP, домены или CIDR и формирует .bat
файл с командами `route add` для роутеров Keenetic.
"""

from flask import Flask, render_template, request, session, send_file, redirect, url_for
from flask_talisman import Talisman
import ipaddress
import socket
import subprocess
import re
import tempfile
import os
import secrets
from datetime import timedelta

app = Flask(__name__)
# Секретный ключ нужен для работы механизма сессий
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(16))
# Время жизни cookie сессии
app.permanent_session_lifetime = timedelta(hours=1)
app.config.update(
    SESSION_COOKIE_SECURE=False,  # Отключено, т.к. проект используется локально
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Talisman добавляет базовые HTTP заголовки безопасности.
# HTTPS отключён, так как приложение предназначено для локального запуска.
Talisman(app, force_https=False)

# Каталог для временных .bat файлов
TEMP_DIR = "tmp"
os.makedirs(TEMP_DIR, exist_ok=True)


@app.before_request
def ensure_temp_file():
    """Создаёт временный .bat файл для текущей сессии, если его ещё нет."""
    if "bat_path" not in session:
        fd, path = tempfile.mkstemp(suffix=".bat", dir=TEMP_DIR)
        os.close(fd)
        session["bat_path"] = path
        # Делаем сессию постоянной, чтобы файл не терялся при переходах
        session.permanent = True

def cidr_to_netmask(cidr: str):
    """Преобразует запись CIDR в пару (network, netmask)."""
    net = ipaddress.ip_network(cidr, strict=False)
    return str(net.network_address), str(net.netmask)

def resolve_domain(domain: str):
    """Возвращает IP адрес доменного имени или None."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

def get_cidrs_from_whois(ip: str):
    """
    Выполняет запрос whois и пытается извлечь CIDR.
    Возвращает список CIDR или пустой список.
    """
    try:
        result = subprocess.run(['whois', ip],
                                capture_output=True,
                                text=True,
                                timeout=10)
        match = re.search(r'^CIDR:\s*(.+)', result.stdout, re.MULTILINE)
        if match:
            return [x.strip() for x in match.group(1).split(',')]
    except Exception:
        pass
    return []

def generate_route_data(input_list):
    """
    Разбирает пользовательский ввод и формирует данные
    для таблицы и итогового .bat файла.
    """
    route_data = []
    errors = []
    seen = set()
    domain_count = 0

    for item in input_list:
        item = item.strip()
        if not item:
            continue

        # Проверяем, похоже ли значение на доменное имя
        if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', item):
            domain_count += 1
            ip = resolve_domain(item)
            if not ip:
                errors.append(f"{item} → ❌ DNS ошибка")
                continue
            cidrs = get_cidrs_from_whois(ip)
            if not cidrs:
                # Fallback: если CIDR не найден, добавляем одиночный IP /32
                network, netmask = ip, '255.255.255.255'
                route = f'route add {network} mask {netmask} 0.0.0.0'
                if route not in seen:
                    seen.add(route)
                    route_data.append((item, ip, f"{network}/32", route))
                errors.append(f"{item} → {ip} → CIDR не найден, добавлен /32")
                continue
            for cidr in cidrs:
                try:
                    network, netmask = cidr_to_netmask(cidr)
                    route = f'route add {network} mask {netmask} 0.0.0.0'
                    if route not in seen:
                        seen.add(route)
                        route_data.append((item, ip, cidr, route))
                except Exception:
                    errors.append(f"{item} → {cidr} → ❌ ошибка")
        else:
            # Обработка ввода как IP-адреса или CIDR
            try:
                if '/' in item:
                    network, netmask = cidr_to_netmask(item)
                    ip_value = network
                else:
                    ip = ipaddress.ip_address(item)
                    ip_value = str(ip)
                    network, netmask = str(ip), '255.255.255.255'
                route = f'route add {network} mask {netmask} 0.0.0.0'
                if route not in seen:
                    seen.add(route)
                    cidr_str = f"{network}/{ipaddress.IPv4Network(network + '/' + netmask).prefixlen}"
                    route_data.append((item, ip_value, cidr_str, route))
            except Exception:
                errors.append(f"{item} → ❌ ошибка IP")

    return route_data, errors, domain_count

@app.route("/", methods=["GET", "POST"])
def index():
    """Главная страница: форма ввода и вывод результатов."""
    route_data, errors, summary, history = [], [], {}, session.get("history", [])

    if request.method == "POST":
        raw_input = request.form.get("input_data", "")
        inputs = raw_input.strip().splitlines()
        route_data, errors, domain_count = generate_route_data(inputs)
        commands = [cmd for _, _, _, cmd in route_data]

        # Сохранить .bat с Windows-переносами строк
        bat_path = session.get("bat_path")
        with open(bat_path, "w", encoding="utf-8") as f:
            f.write("\r\n".join(commands))

        # Обновить историю запросов (храним последние 10)
        history_entry = {"count": len(commands), "input": inputs}
        history.insert(0, history_entry)
        session["history"] = history[:10]

        summary = {
            "total": len(commands),
            "unique_ips": len(set(x[1] for x in route_data)),
            "domains": domain_count,
        }

    return render_template(
        "index.html",
        route_data=route_data,
        errors=errors,
        summary=summary,
        history=session.get("history", []),
    )

@app.route("/download")
def download():
    """Отдаёт пользователю сформированный .bat файл."""
    bat_path = session.get("bat_path")
    if bat_path and os.path.exists(bat_path):
        return send_file(bat_path, as_attachment=True, download_name="routes.bat")
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Запуск приложения
    app.run(host="0.0.0.0", port=2022)
