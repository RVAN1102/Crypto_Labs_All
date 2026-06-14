import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

INPUT_CANDIDATES = [
    ROOT / "artifacts" / "windows" / "bench" / "bench_windows_summary.csv",
    ROOT / "bench_windows_summary.csv",
]

OUT_PATH = ROOT / "report" / "assets" / "windows_benchmark_tables.md"
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)


def find_input_csv():
    for path in INPUT_CANDIDATES:
        if path.exists():
            return path
    raise FileNotFoundError("Cannot find bench_windows_summary.csv")


def size_label(n):
    n = int(n)
    if n >= 1024 * 1024:
        return f"{n // (1024 * 1024)} MiB"
    if n >= 1024:
        return f"{n // 1024} KiB"
    return f"{n} B"


def load_rows(path):
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["payload_bytes"] = int(row["payload_bytes"])
            row["mean_ms_per_op"] = float(row["mean_ms_per_op"])
            row["median_ms_per_op"] = float(row["median_ms_per_op"])
            row["stddev_ms_per_op"] = float(row["stddev_ms_per_op"])
            row["ci95_ms_per_op"] = float(row["ci95_ms_per_op"])
            row["mean_mib_s"] = float(row["mean_mib_s"])
            row["median_mib_s"] = float(row["median_mib_s"])
            row["stddev_mib_s"] = float(row["stddev_mib_s"])
            row["ci95_mib_s"] = float(row["ci95_mib_s"])
            rows.append(row)
    return rows


def make_table(rows, operation, payload_size):
    selected = [
        r for r in rows
        if r["operation"] == operation and r["payload_bytes"] == payload_size
    ]

    selected.sort(key=lambda r: r["mean_mib_s"], reverse=True)

    lines = []
    lines.append(f"### Windows {operation} benchmark at {size_label(payload_size)}")
    lines.append("")
    lines.append("| Mode | Mean throughput (MiB/s) | 95% CI throughput | Mean latency (ms/op) | 95% CI latency |")
    lines.append("|---|---:|---:|---:|---:|")

    for r in selected:
        lines.append(
            f"| {r['mode']} | "
            f"{r['mean_mib_s']:.2f} | "
            f"±{r['ci95_mib_s']:.2f} | "
            f"{r['mean_ms_per_op']:.6f} | "
            f"±{r['ci95_ms_per_op']:.6f} |"
        )

    lines.append("")
    return "\n".join(lines)


def make_full_coverage_summary(rows):
    modes = sorted({r["mode"] for r in rows})
    operations = sorted({r["operation"] for r in rows})
    sizes = sorted({r["payload_bytes"] for r in rows})

    lines = []
    lines.append("# Windows Benchmark Tables")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Total summary rows: {len(rows)}")
    lines.append(f"- Modes: {', '.join(modes)}")
    lines.append(f"- Operations: {', '.join(operations)}")
    lines.append(f"- Payload sizes: {', '.join(size_label(s) for s in sizes)}")
    lines.append("")

    expected = 8 * 2 * 6
    if len(rows) == expected:
        lines.append(f"Coverage check: PASS. Expected {expected} rows and got {len(rows)} rows.")
    else:
        lines.append(f"Coverage check: WARNING. Expected {expected} rows but got {len(rows)} rows.")

    lines.append("")
    return "\n".join(lines)


def main():
    input_csv = find_input_csv()
    rows = load_rows(input_csv)

    output = []
    output.append(make_full_coverage_summary(rows))

    for size in [1024, 16 * 1024, 1024 * 1024, 8 * 1024 * 1024]:
        output.append(make_table(rows, "encrypt", size))
        output.append(make_table(rows, "decrypt", size))

    OUT_PATH.write_text("\n".join(output), encoding="utf-8")

    print(f"Input CSV: {input_csv}")
    print(f"Output table file: {OUT_PATH}")
    print("Done.")


if __name__ == "__main__":
    main()