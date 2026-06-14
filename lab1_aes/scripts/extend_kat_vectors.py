import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

IN_PATH = ROOT / "vectors" / "aes_kat_sample.json"
OUT_PATH = ROOT / "vectors" / "aes_kat_extended.json"


def detect_cases_root(doc):
    if isinstance(doc, dict) and "cases" in doc and isinstance(doc["cases"], list):
        return doc["cases"]
    if isinstance(doc, list):
        return doc
    raise ValueError("Unsupported KAT JSON format. Expected object with 'cases' list or a list.")


def detect_field_name(sample_case, plain_name, hex_name):
    if hex_name in sample_case:
        return hex_name
    if plain_name in sample_case:
        return plain_name
    return hex_name


def make_case(field, name, mode, key, plaintext, ciphertext, iv=None):
    c = {}
    c[field["name"]] = name
    c[field["mode"]] = mode
    c[field["key"]] = key
    if iv is not None:
        c[field["iv"]] = iv
    c[field["plaintext"]] = plaintext
    c[field["ciphertext"]] = ciphertext
    return c


def main():
    if not IN_PATH.exists():
        raise FileNotFoundError(f"Missing input KAT file: {IN_PATH}")

    doc = json.loads(IN_PATH.read_text(encoding="utf-8"))
    cases = detect_cases_root(doc)

    if not cases:
        raise ValueError("Input KAT file has no cases.")

    sample = cases[0]

    field = {
        "name": "name" if "name" in sample else "id",
        "mode": "mode",
        "key": detect_field_name(sample, "key", "key_hex"),
        "iv": detect_field_name(sample, "iv", "iv_hex"),
        "plaintext": detect_field_name(sample, "plaintext", "plaintext_hex"),
        "ciphertext": detect_field_name(sample, "ciphertext", "ciphertext_hex"),
    }

    plaintext_4_blocks = (
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710"
    )

    new_cases = [
        make_case(
            field,
            "FIPS-197 AES-192 ECB single block",
            "ecb",
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "6bc1bee22e409f96e93d7e117393172a",
            "bd334f1d6e45f25ff712a214571fa5cc"
        ),
        make_case(
            field,
            "FIPS-197 AES-256 ECB single block",
            "ecb",
            "603deb1015ca71be2b73aef0857d77811"
            "1f352c073b6108d72d9810a30914dff4",
            "6bc1bee22e409f96e93d7e117393172a",
            "f3eed1bdb5d2a03c064b5a7e3db181f8"
        ),
        make_case(
            field,
            "NIST SP800-38A AES-128 CBC 4 blocks",
            "cbc",
            "2b7e151628aed2a6abf7158809cf4f3c",
            plaintext_4_blocks,
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7",
            "000102030405060708090a0b0c0d0e0f"
        ),
        make_case(
            field,
            "NIST SP800-38A AES-128 CFB128 4 blocks",
            "cfb",
            "2b7e151628aed2a6abf7158809cf4f3c",
            plaintext_4_blocks,
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "c8a64537a0b3a93fcde3cdad9f1ce58b"
            "26751f67a3cbb140b1808cf187a4f4df"
            "c04b05357c5d1c0eeac4c66f9ff7f2e6",
            "000102030405060708090a0b0c0d0e0f"
        ),
        make_case(
            field,
            "NIST SP800-38A AES-128 OFB 4 blocks",
            "ofb",
            "2b7e151628aed2a6abf7158809cf4f3c",
            plaintext_4_blocks,
            "3b3fd92eb72dad20333449f8e83cfb4a"
            "7789508d16918f03f53c52dac54ed825"
            "9740051e9c5fecf64344f7a82260edcc"
            "304c6528f659c77866a510d9c1d6ae5e",
            "000102030405060708090a0b0c0d0e0f"
        ),
        make_case(
            field,
            "NIST SP800-38A AES-128 CTR 4 blocks",
            "ctr",
            "2b7e151628aed2a6abf7158809cf4f3c",
            plaintext_4_blocks,
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
        ),
    ]

    existing_names = set()
    for c in cases:
        if field["name"] in c:
            existing_names.add(c[field["name"]])

    appended = 0

    for c in new_cases:
        if c[field["name"]] not in existing_names:
            cases.append(c)
            appended += 1

    OUT_PATH.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    print(f"Input: {IN_PATH}")
    print(f"Output: {OUT_PATH}")
    print(f"Original cases plus appended cases written.")
    print(f"Appended: {appended}")
    print(f"Total cases: {len(cases)}")


if __name__ == "__main__":
    main()