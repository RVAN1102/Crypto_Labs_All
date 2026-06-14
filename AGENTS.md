\# Project instructions for Codex



This repository implements Cryptography \& Applications labs. Lab 2 is intentionally skipped. Do not create, implement, or modify Lab 2.



Work one lab and one milestone at a time. Do not implement multiple labs in one pass unless explicitly requested.



Use the same engineering standard as Lab 1:



\* Modern C++17 or later.

\* CMake out-of-source builds.

\* Windows MinGW64 and Ubuntu/Linux compatibility.

\* CLI tools with consistent command structure.

\* Binary-safe file I/O.

\* UTF-8 text input.

\* Hex/base64/raw encoding options where relevant.

\* Fail closed on malformed input.

\* Secure randomness only: Crypto++ AutoSeededRandomPool or OpenSSL RAND\_bytes.

\* Never use rand() or std::random for cryptographic keys, IVs, nonces, salts, or secrets.

\* Use std::random only for synthetic benchmark data when needed.

\* Include KAT runner where applicable.

\* Include extended vectors, not only one sample vector.

\* Include GoogleTest unit tests.

\* Integrate all tests into CTest.

\* Include negative tests.

\* Include benchmark runner with CSV output.

\* Include artifacts/logs for Windows and Linux.

\* Do not generate DOCX or PDF reports unless explicitly requested.

\* Markdown notes, README updates, benchmark tables, plots, and logs are allowed.

\* Do not silently remove existing working Lab 1 files.

\* Do not change cryptographic parameters away from lab requirements.



Crypto preferences:



\* For symmetric encryption, prefer AES-256-GCM unless the lab explicitly requires another algorithm or mode.

\* For hashing, prefer SHA3-512 unless the lab explicitly requires SHA-256, SHA-512, SHA3-256, or another algorithm.

\* If the lab explicitly specifies SHA-256, OAEP(SHA-256), RSA-PSS(SHA-256), or another parameter, follow the lab specification.



Required per lab:



1\. Implement core crypto functions.

2\. Implement CLI.

3\. Implement file formats and metadata.

4\. Implement KAT.

5\. Implement negative tests.

6\. Implement GoogleTest unit tests.

7\. Integrate CTest.

8\. Implement benchmark runner.

9\. Generate Windows artifacts.

10\. Generate Linux artifacts.

11\. Update README.

12\. Create self-grade checklist.

13\. Create academic integrity and AI assistance note.



Before changing code:



\* Inspect the existing directory.

\* Summarize what exists.

\* Propose a short milestone plan.

\* Then implement only the current milestone.



After changing code:



\* Build.

\* Run unit tests.

\* Run CTest.

\* Show exact commands and results.

\* Save logs under artifacts/<platform>/logs.



