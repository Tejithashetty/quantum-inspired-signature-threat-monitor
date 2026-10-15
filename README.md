# Quantum-Inspired Digital Signature Threat Monitor

A live student research prototype for signed-message verification and behavioral threat scoring. It accepts real submissions through a FastAPI endpoint and Streamlit form, stores events in local SQLite for development or managed PostgreSQL when `DATABASE_URL` is configured, and displays detector results and alerts.

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

Open the URL shown in the terminal, usually http://localhost:8501. The Streamlit app calls the shared analysis service directly, so it runs by itself locally and on Streamlit Community Cloud. Without `DATABASE_URL`, it uses a local SQLite file. With `DATABASE_URL`, it uses PostgreSQL.

To also run the JSON API locally, open another activated terminal and run:

```cmd
python -m uvicorn app.main:app --reload
```

API documentation is at http://127.0.0.1:8000/docs. The API and Streamlit use the same configured event store and detector service.

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
4. **ML detector** trains an Isolation Forest on prior validly signed, LOW-risk events from that key. It stays in warm-up until 20 real low-risk events are available; suspicious but valid events are excluded to reduce baseline poisoning.
5. **Quantum-inspired detector** evaluates a QUBO-style feature-interaction score using ordinary classical arithmetic. It does not use quantum hardware and makes no quantum-advantage claim.
6. **Hybrid decision** combines statistical (40%), QUBO-style (30%), and ML (30%) scores. During ML warm-up, active scores are renormalized. The adaptive threshold uses the key's previous 10 valid LOW-risk events; before that, a default of 40 is shown.
7. **Risk and alerts** classify events as LOW, MEDIUM, HIGH, or CRITICAL. Both dashboards refresh every five seconds.

The system does not insert generated data into its learning baseline. Detector warm-up uses only events submitted to the application.

## Security and privacy

- `keys/private_key.pem` stays local and is excluded from Git. Never share or upload it.
- Raw message contents are used in memory for signature verification and feature extraction, then discarded. The database stores a keyed HMAC fingerprint instead of the message text, along with signatures, public keys, features, scores, and alerts. In local SQLite mode, the HMAC key is generated in `keys/fingerprint.key`; in PostgreSQL mode, it comes from the `FINGERPRINT_KEY` secret. A fingerprint is a stable pseudonymous identifier, not anonymization.
- The fingerprint key is needed to match repeated messages. Keep it private, back it up securely, and do not change it after events have been stored. This is still a student demo, not a guarantee of production-grade privacy.
- The Streamlit Community Cloud demo is publicly accessible. It has no user authentication, rate limiting, or production data-retention controls. Submit only made-up test messages and test keys. Do not submit confidential messages, real customer data, or production signatures. Anyone who can open the app can submit events and view the shared event monitor.
- Streamlit Community Cloud does not guarantee persistence of local file storage. To retain hosted event history, configure a managed PostgreSQL database and set both `DATABASE_URL` and `FINGERPRINT_KEY` as Streamlit secrets. Existing hosted SQLite history is not automatically copied into PostgreSQL.

## Current evaluation notes

Manual live checks completed in the hosted app:

| Scenario | Observed behavior |
| --- | --- |
| Valid signed message | Signature verified; low-risk examples scored below the alert threshold. |
| Message changed after signing | Signature verification failed and the event was raised as high risk. |
| Repeated valid message | Signature remained valid; repeated-message behavior raised the risk score. |
| ML warm-up | After enough low-risk valid live events, the app displayed an ML anomaly score. One event had an ML score of 96.2 while its hybrid score stayed below the threshold and its final risk remained LOW. This score is a ranking signal, not a probability; the weighted hybrid decision can differ from an individual detector. |

The burst-rate case has not been manually confirmed. These checks are prototype demonstrations, not a measured scientific benchmark. For a formal evaluation, record the number of events per scenario, expected result, observed result, and false-positive/false-negative counts using made-up data.

## Configure managed PostgreSQL for Streamlit Community Cloud

1. Create a PostgreSQL project with a managed provider, such as Supabase.
2. In the provider dashboard, copy the **session pooler** connection string for the hosted app. Replace its password placeholder with your database password. Keep the completed string private.
3. Generate a long random fingerprint secret locally. In PowerShell, run `python -c "import secrets; print(secrets.token_urlsafe(32))"` and keep the result private.
4. In Streamlit Community Cloud, open the app menu, select **Settings → Secrets**, and add:

   ```toml
   DATABASE_URL = "paste-your-private-postgres-connection-string"
   FINGERPRINT_KEY = "paste-the-random-secret"
   ```

5. Save the secrets and let the app restart. On startup, the app creates or updates the `events` table automatically. Submit a made-up signed message, refresh the app, and check that the event remains in the Live monitor.

Never commit database credentials or `FINGERPRINT_KEY` to GitHub. The project `.gitignore` excludes `.streamlit/secrets.toml` for local secrets.

## Research contribution

The project contribution is system-level integration: digital-signature event analysis with statistical, ML, and QUBO-inspired scores, hybrid decision-making, adaptive risk classification, live input, and alert display. It does not claim to invent a new cryptographic algorithm or prove quantum advantage.
