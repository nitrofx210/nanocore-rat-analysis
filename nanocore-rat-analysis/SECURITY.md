# Security Policy

## Responsible Disclosure

This is a **research repository** for malware analysis.

⚠️ **Do not submit actual malware samples as issues or pull requests.**

If you find a bug in the detection scripts or ML pipeline:
- Open a GitHub Issue with label `bug`
- Describe the expected vs actual behaviour
- Include Python version and OS

## Safe Usage Guidelines

1. **Always use FLARE-VM or equivalent isolated sandbox** for any dynamic analysis
2. **Never run** `*.exe` files from `docs/screenshots` — they are screenshot images, not executables
3. **Kaggle dataset CSVs** contain feature vectors only — no executable code
4. The Streamlit app performs **static analysis only** via `pefile` — safe on any machine
5. MalwareBazaar API queries metadata only by default — no binary downloads

## What This Repo Does NOT Contain

- ❌ NanoCore RAT executable binaries
- ❌ Malware source code
- ❌ Exploits or weaponized payloads
- ✅ Feature vectors from benign + malicious PE files (CSV)
- ✅ Screenshots of analysis tools
- ✅ Python ML code and Streamlit app
