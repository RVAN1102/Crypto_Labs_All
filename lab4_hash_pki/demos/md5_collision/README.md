# MD5 Collision Demo Scaffold

This directory is reserved for a controlled, offline MD5 collision demonstration using hashclash. No collision files are committed here, and this README does not claim the collision has been completed.

## Requirements

The generation script requires hashclash tooling, preferably on Ubuntu. If hashclash is unavailable on Windows, run this demo on Ubuntu.

The demo must produce two benign offline files:

- `collision_a.bin`
- `collision_b.bin`

The demo is successful only when both are true:

- The two files have the same MD5 digest.
- The two files have different SHA-256 digests.

Use the verification scripts to check those properties. Do not use this demo against live targets, public websites, third-party files, real certificates, or production systems.

## Collision Is Not Preimage

An MD5 collision means two different messages have the same MD5 digest. It does not mean an attacker can choose an arbitrary existing digest and find a file matching it. That harder problem is a preimage attack. This lab demonstrates collision weakness only.

## Generate on Ubuntu

Install or build hashclash so that a compatible `md5_fastcoll` or `fastcoll` command is available on `PATH`, then run:

```bash
bash lab4_hash_pki/scripts/md5_collision_demo_linux.sh
```

The script writes result files only after it generates real candidate files and verifies that MD5 matches while SHA-256 differs.

## Verify on Linux

```bash
bash lab4_hash_pki/scripts/verify_md5_collision.sh
```

Expected success output:

```text
MD5 collision verification: PASS
SHA-256 difference verification: PASS
```

## Verify Existing Files on Windows

Windows verification is supported for existing generated files:

```powershell
powershell -ExecutionPolicy Bypass -File lab4_hash_pki\scripts\verify_md5_collision_windows.ps1
```

The Windows script does not generate collisions. It only verifies `collision_a.bin` and `collision_b.bin` if they already exist.

