"""Генератор великого access.log для вимірювання продуктивності.

Запуск: python -m tools.generate_log 200000 logs/big.log
"""

import random
import sys
from datetime import datetime, timedelta, timezone

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
TZ = timezone(timedelta(hours=2))
START = datetime(2026, 11, 16, tzinfo=TZ)
DAYS = 7

BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
           "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36")
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
EMAIL_BOT = "Mozilla/5.0 (compatible; email-guesser/1.0)"
HIDDEN = ["/.git/HEAD", "/.git/config", "/.env", "/wp-login.php",
          "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/"]
MISSING = ["/contact", "/about", "/team", "/staff", "/people", "/leadership"]


def stamp(moment: datetime) -> str:
    return (f"{moment.day:02d}/{MONTHS[moment.month - 1]}/{moment.year}:"
            f"{moment:%H:%M:%S} +0200")


def make_line(ip, moment, path, status, size, referer, agent) -> tuple[datetime, str]:
    text = (f'{ip} - - [{stamp(moment)}] "GET {path} HTTP/1.0" '
            f'{status} {size} "{referer}" "{agent}"')
    return moment, text


def main() -> None:
    total = int(sys.argv[1]) if len(sys.argv) > 1 else 200_000
    out = sys.argv[2] if len(sys.argv) > 2 else "logs/big.log"
    random.seed(42)

    used: set[str] = set()

    def new_ip() -> str:
        while True:
            ip = ".".join(str(random.randint(1, 223)) for _ in range(4))
            if ip not in used:
                used.add(ip)
                return ip

    def random_moment() -> datetime:
        return START + timedelta(seconds=random.randint(0, DAYS * 86400 - 1))

    lines: list[tuple[datetime, str]] = []

    # Атаки (їх небагато, як у реальному житті)
    n_scan = total // 2000
    n_burst = total // 2000
    n_bots = total // 5000

    for _ in range(n_scan):  # сканування прихованих файлів
        ip, moment = new_ip(), random_moment()
        for i, path in enumerate(random.sample(HIDDEN, random.randint(1, 3))):
            lines.append(make_line(ip, moment + timedelta(seconds=i), path,
                                   404, 392, "-", BROWSER))

    for _ in range(n_burst):  # багато 404 за хвилину
        ip, moment = new_ip(), random_moment()
        for i in range(random.randint(10, 30)):
            path = f"/assets/images/missing{random.randint(1, 999)}.png"
            lines.append(make_line(ip, moment + timedelta(seconds=i * 2), path,
                                   404, 400, "-", BROWSER))

    for _ in range(n_bots):  # бот-збирач пошти
        ip, moment = new_ip(), random_moment()
        for i, path in enumerate(MISSING + MISSING[:4]):
            lines.append(make_line(ip, moment + timedelta(seconds=i), path,
                                   404, 390, "-", EMAIL_BOT))

    # Звичайний трафік
    pool = [new_ip() for _ in range(max(1000, total // 40))]
    googlebots = [new_ip() for _ in range(20)]
    while len(lines) < total:
        moment = random_moment()
        roll = random.random()
        if roll < 0.15:
            ip, agent = random.choice(googlebots), GOOGLEBOT
        else:
            ip, agent = random.choice(pool), BROWSER
        if random.random() < 0.9:
            path = f"/view_article.php?id={random.randint(1, 700)}"
            status, size = 200, random.randint(2000, 25000)
        else:
            path = f"/old/page{random.randint(1, 500)}.php"
            status, size = 404, 400
        lines.append(make_line(ip, moment, path, status, size, "-", agent))

    lines.sort(key=lambda item: item[0])
    with open(out, "w", encoding="utf-8") as file:
        for _, text in lines:
            file.write(text + "\n")

    print(f"Записано {len(lines)} рядків у {out}")
    print(f"Закладено: сканувань {n_scan}, сплесків 404 {n_burst}, ботів {n_bots}")


if __name__ == "__main__":
    main()