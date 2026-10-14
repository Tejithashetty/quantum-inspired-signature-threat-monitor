# Quantum-Inspired Digital Signature Threat Monitor

A live student research prototype for signed-message verification and behavioral threat scoring. It accepts real submissions through a FastAPI endpoint and Streamlit form, stores events in SQLite, and displays detector results and alerts.

## Requirements

- Python 3.14.3
- Internet access to install packages

## Install on Windows

Use Command Prompt or PowerShell in the project folder. If your Python environment has incorrect `PYTHONHOME` or `PYTHONPATH` values, clear them in each terminal first.

Command Prompt:

```cmd
set PYTHONHOME=
set PYTHONPATH=
py -3.14 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

PowerShell:

```powershell
$env:PYTHONHOME = ""
$env:PYTHONPATH = ""
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Start the live application

Start the Streamlit interface from the project root:

```cmd
python -m streamlit run streamlit_app.py
```

Open the URL shown in the terminal, usually http://localhost:8501. The Streamlit app calls the shared analysis service directly, so it runs by itself locally and on Streamlit Community Cloud.

To also run the JSON API locally, open another activated terminal and run:

```cmd
python -m uvicorn app.main:app --reload
```

API documentation is at http://127.0.0.1:8000/docs. The API and Streamlit use the same local SQLite event store and detector service.

Run the project checks with:

```cmd
python -m pytest
```

## Submit real signed messages

In another activated terminal, run:

```cmd
python sign_message.py
```

Enter a made-up test message. The script signs it locally and prints the message, Base64 public key, and signature. Paste those three values into the Streamlit **Submit live event** tab and select **Analyze event**. The app reports signature validity, detector scores, risk level, threshold, and alert reasons.

To test tampering, change the message after signing it and submit the old signature. The signature check should fail. To test a burst, submit several signed events from the same key in a short period.

The API also accepts JSON at `POST /api/events`; `GET /api/events` returns recent records.

## Detection pipeline

1. **Ed25519 verification** checks that the message matches the supplied public key and signature.
2. **Feature extraction** measures message length, event count per key over one minute, repeated-message count over five minutes, and verification/empty/long-message flags.
3. **Statistical detector** applies transparent rules and a median/MAD comparison against the key's real message-length history.
4. **ML detector** trains an Isolation Forest on prior validly signed events from that key. It stays in warm-up until 20 real valid events are available.
5. **Quantum-inspired detector** evaluates a QUBO-style feature-interaction score using ordinary classical arithmetic. It does not use quantum hardware and makes no quantum-advantage claim.
6. **Hybrid decision** combines statistical (40%), QUBO-style (30%), and ML (30%) scores. During ML warm-up, active scores are renormalized. The adaptive threshold uses the key's previous 10 valid events; before that, a default of 40 is shown.
7. **Risk and alerts** classify events as LOW, MEDIUM, HIGH, or CRITICAL. Both dashboards refresh every five seconds.

The system does not insert generated data into its learning baseline. Detector warm-up uses only events submitted to the application.

## Security and privacy

- `keys/private_key.pem` stays local and is excluded from Git. Never share or upload it.
- Raw message contents are used in memory for signature verification and feature extraction, then discarded. The database stores a keyed HMAC fingerprint instead of the message text, along with signatures, public keys, features, scores, and alerts. The local HMAC secret is generated in `keys/fingerprint.key`, which is excluded from Git. Earlier plaintext demo messages are converted to fingerprints when the API starts.
- The local fingerprint key is needed to match repeated messages. Keep the `keys` folder private and do not upload it. This is still a student demo, not a guarantee of production-grade privacy.
- This is a development demo without user authentication, HTTPS, rate limiting, or production data-retention controls. Do not expose it publicly until those protections are added.
- Streamlit Community Cloud does not guarantee persistence of local file storage. The hosted demo may lose its SQLite history and local fingerprint key after a restart; use a managed database and secret store for persistent deployment.

## Research contribution

The project contribution is system-level integration: digital-signature event analysis with statistical, ML, and QUBO-inspired scores, hybrid decision-making, adaptive risk classification, live input, and alert display. It does not claim to invent a new cryptographic algorithm or prove quantum advantage.
