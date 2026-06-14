import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "vectors" / "aes_kat_extended.json"


def copy_if_missing(case, target, candidates):
    if target in case:
        return

    for name in candidates:
        if name in case:
            case[target] = case[name]
            return


def main():
    if not PATH.exists():
        raise FileNotFoundError(f"Missing file: {PATH}")

    doc = json.loads(PATH.read_text(encoding="utf-8"))

    if isinstance(doc, dict) and "cases" in doc:
        cases = doc["cases"]
    elif isinstance(doc, list):
        cases = doc
    else:
        raise ValueError("Unsupported KAT JSON format.")

    fixed = 0

    for case in cases:
        before = dict(case)

        copy_if_missing(case, "key", ["key_hex"])
        copy_if_missing(case, "iv", ["iv_hex", "nonce", "nonce_hex"])
        copy_if_missing(case, "pt", ["plaintext", "plaintext_hex"])
        copy_if_missing(case, "ct", ["ciphertext", "ciphertext_hex"])
        copy_if_missing(case, "aad", ["aad_hex"])
        copy_if_missing(case, "tag", ["tag_hex"])

        if case != before:
            fixed += 1

    PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    print(f"Fixed cases: {fixed}")
    print(f"Written: {PATH}")


if __name__ == "__main__":
    main()