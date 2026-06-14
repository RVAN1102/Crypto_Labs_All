import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PATH = ROOT / "vectors" / "aes_kat_extended.json"


def main():
    doc = json.loads(PATH.read_text(encoding="utf-8"))

    if isinstance(doc, dict) and "cases" in doc:
        cases = doc["cases"]
    elif isinstance(doc, list):
        cases = doc
    else:
        raise ValueError("Unsupported KAT JSON format.")

    patched = False

    for case in cases:
        name = case.get("name", case.get("id", ""))

        if "AES-256 ECB" in name:
            case["name"] = "FIPS-197 AES-256 ECB single block"
            case["mode"] = "ecb"

            case["key"] = (
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f"
            )

            case["pt"] = "00112233445566778899aabbccddeeff"
            case["ct"] = "8ea2b7ca516745bfeafc49904b496089"

            # Remove alternative schema fields to avoid ambiguity.
            for k in [
                "key_hex",
                "plaintext",
                "plaintext_hex",
                "ciphertext",
                "ciphertext_hex"
            ]:
                case.pop(k, None)

            patched = True

    if not patched:
        raise RuntimeError("AES-256 ECB case not found.")

    PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    print(f"Patched AES-256 ECB vector in: {PATH}")


if __name__ == "__main__":
    main()