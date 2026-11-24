from collections import Counter

from loganalyzer.parsing.reader import ParseStats, read_entries

stats = ParseStats()
ips: Counter[str] = Counter()
statuses: Counter[int] = Counter()

for entry in read_entries("access.log", stats):
    ips[entry.ip] += 1
    statuses[entry.status] += 1

print(f"Усього рядків: {stats.total}")
print(f"Розібрано:     {stats.parsed}")
print(f"Битих:         {stats.errors}")
for number, text in stats.bad_lines:
    print(f"  рядок {number}: {text}")

print("\nТоп-5 IP:")
for ip, count in ips.most_common(5):
    print(f"  {ip:<18} {count}")

print("\nСтатуси:")
for status, count in sorted(statuses.items()):
    print(f"  {status}: {count}")