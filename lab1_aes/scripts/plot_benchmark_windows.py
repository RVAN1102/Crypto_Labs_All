import csv
from pathlib import Path
from collections import defaultdict

import matplotlib.pyplot as plt


ROOT = Path(__file__).resolve().parent.parent

INPUT_CANDIDATES = [
    ROOT / "artifacts" / "windows" / "bench" / "bench_windows_summary.csv",
    ROOT / "bench_windows_summary.csv",
]

OUT_DIR = ROOT / "report" / "assets"
OUT_DIR.mkdir(parents=True, exist_ok=True)


def find_input_csv():
    for path in INPUT_CANDIDATES:
        if path.exists():
            return path
    raise FileNotFoundError("Cannot find bench_windows_summary.csv")


def load_rows(path):
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({
                "platform": row["platform"],
                "mode": row["mode"],
                "operation": row["operation"],
                "payload_bytes": int(row["payload_bytes"]),
                "mean_ms_per_op": float(row["mean_ms_per_op"]),
                "ci95_ms_per_op": float(row["ci95_ms_per_op"]),
                "mean_mib_s": float(row["mean_mib_s"]),
                "ci95_mib_s": float(row["ci95_mib_s"]),
            })
    return rows


def size_label(n):
    if n >= 1024 * 1024:
        return f"{n // (1024 * 1024)} MiB"
    if n >= 1024:
        return f"{n // 1024} KiB"
    return f"{n} B"


def group_rows(rows, operation):
    grouped = defaultdict(list)
    for row in rows:
        if row["operation"] == operation:
            grouped[row["mode"]].append(row)

    for mode in grouped:
        grouped[mode].sort(key=lambda r: r["payload_bytes"])

    return grouped


def plot_throughput(rows, operation, output_name):
    grouped = group_rows(rows, operation)

    plt.figure(figsize=(11, 6))

    for mode in sorted(grouped.keys()):
        data = grouped[mode]
        x = [r["payload_bytes"] for r in data]
        y = [r["mean_mib_s"] for r in data]
        yerr = [r["ci95_mib_s"] for r in data]
        plt.errorbar(x, y, yerr=yerr, marker="o", capsize=3, label=mode)

    sizes = sorted({r["payload_bytes"] for r in rows})
    plt.xscale("log", base=2)
    plt.xticks(sizes, [size_label(s) for s in sizes], rotation=30)
    plt.xlabel("Payload size")
    plt.ylabel("Throughput (MiB/s)")
    plt.title(f"AES {operation} throughput on Windows/MinGW64")
    plt.grid(True, which="both", linewidth=0.5)
    plt.legend()
    plt.tight_layout()

    out_path = OUT_DIR / output_name
    plt.savefig(out_path, dpi=180)
    plt.close()
    print(f"Saved {out_path}")


def plot_latency(rows, operation, output_name):
    grouped = group_rows(rows, operation)

    plt.figure(figsize=(11, 6))

    for mode in sorted(grouped.keys()):
        data = grouped[mode]
        x = [r["payload_bytes"] for r in data]
        y = [r["mean_ms_per_op"] for r in data]
        yerr = [r["ci95_ms_per_op"] for r in data]
        plt.errorbar(x, y, yerr=yerr, marker="o", capsize=3, label=mode)

    sizes = sorted({r["payload_bytes"] for r in rows})
    plt.xscale("log", base=2)
    plt.yscale("log")
    plt.xticks(sizes, [size_label(s) for s in sizes], rotation=30)
    plt.xlabel("Payload size")
    plt.ylabel("Latency (ms/op)")
    plt.title(f"AES {operation} latency on Windows/MinGW64")
    plt.grid(True, which="both", linewidth=0.5)
    plt.legend()
    plt.tight_layout()

    out_path = OUT_DIR / output_name
    plt.savefig(out_path, dpi=180)
    plt.close()
    print(f"Saved {out_path}")


def main():
    input_csv = find_input_csv()
    print(f"Using input CSV: {input_csv}")

    rows = load_rows(input_csv)

    modes = sorted({r["mode"] for r in rows})
    operations = sorted({r["operation"] for r in rows})
    sizes = sorted({r["payload_bytes"] for r in rows})

    print("Rows:", len(rows))
    print("Modes:", ", ".join(modes))
    print("Operations:", ", ".join(operations))
    print("Sizes:", ", ".join(size_label(s) for s in sizes))

    if len(rows) != 96:
        print("WARNING: expected 96 summary rows for 8 modes x 2 operations x 6 sizes.")

    plot_throughput(rows, "encrypt", "windows_encrypt_throughput.png")
    plot_throughput(rows, "decrypt", "windows_decrypt_throughput.png")
    plot_latency(rows, "encrypt", "windows_encrypt_latency.png")
    plot_latency(rows, "decrypt", "windows_decrypt_latency.png")


if __name__ == "__main__":
    main()