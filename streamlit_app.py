import requests
import streamlit as st

st.set_page_config(page_title="Signature Threat Monitor", page_icon="🔐", layout="wide")
st.title("Digital Signature Threat Monitor")
st.caption("Live Ed25519 verification with statistical, ML, and QUBO-style risk analysis.")

api_url = st.sidebar.text_input("API address", "http://127.0.0.1:8000").rstrip("/")
st.sidebar.info("Start the API in another terminal with: python -m uvicorn app.main:app --reload")

input_tab, monitor_tab, about_tab = st.tabs(["Submit live event", "Live monitor", "How detection works"])

with input_tab:
    st.subheader("Submit a signed message")
    st.write("Sign a made-up test message with `python sign_message.py`, then paste the message, public key, and signature below.")
    with st.form("submit_event"):
        message = st.text_area("Message", height=120, max_chars=10000)
        public_key = st.text_input("Ed25519 public key (Base64)")
        signature = st.text_area("Signature (Base64)", height=80)
        submitted = st.form_submit_button("Analyze event", type="primary")
    if submitted:
        try:
            response = requests.post(
                f"{api_url}/api/events",
                json={"message": message, "public_key": public_key, "signature": signature},
                timeout=15,
            )
            if response.ok:
                result = response.json()
                st.success(f"Event #{result['id']} analyzed — {result['risk_level']} risk, score {result['risk_score']}/100")
                st.json(result)
            else:
                st.error(f"API returned HTTP {response.status_code}: {response.text}")
        except requests.RequestException as error:
            st.error(f"Could not reach the API at {api_url}. Is the FastAPI server running? Details: {error}")

@st.fragment(run_every="5s")
def render_live_monitor():
    st.subheader("Recent live events")
    st.caption("This view refreshes every five seconds. The original message is not stored; a keyed fingerprint is shown.")
    try:
        response = requests.get(f"{api_url}/api/events", timeout=10)
        response.raise_for_status()
        events = response.json()
        if events:
            for event in events:
                with st.container(border=True):
                    title = f"Event #{event['id']} · {event.get('risk_level', 'UNKNOWN')} risk · score {event['risk_score']}"
                    st.markdown(f"### {title}")
                    left, center, right = st.columns(3)
                    left.metric("Signature", "Valid" if event["verified"] else "INVALID")
                    center.metric("Statistical", f"{event.get('statistical_score', 0):.1f}")
                    right.metric("Quantum-inspired", f"{event.get('quantum_score', 0):.1f}")
                    st.write("**Message HMAC fingerprint:**", event["message"])
                    st.write("**Alert / reason:**", event["reasons"])
                    st.caption(f"Received: {event['received_at']} UTC · ML score: {event.get('ml_score') if event.get('ml_score') is not None else 'warming up'} · Threshold: {event.get('adaptive_threshold', 40)}")
        else:
            st.info("No events submitted yet. Use the Submit live event tab or POST /api/events.")
    except requests.RequestException as error:
        st.error(f"Could not reach the API at {api_url}. Start FastAPI first. Details: {error}")


with monitor_tab:
    render_live_monitor()

with about_tab:
    st.subheader("Detection pipeline")
    st.markdown("""
    1. **Ed25519 verification** checks message integrity against the supplied public key and signature.
    2. **Feature extraction** measures message size, key event rate, repeated messages, and verification outcome.
    3. **Statistical analysis** uses transparent rules and a robust baseline from real events.
    4. **ML analysis** uses Isolation Forest trained on at least 20 prior valid events from this key. It reports warming-up status until then.
    5. **Quantum-inspired analysis** scores QUBO-style interactions using classical arithmetic. No quantum computer or quantum advantage is claimed.
    6. **Hybrid scoring and risk classification** combines detector scores and uses an adaptive threshold after enough real history is available.

    This is a local student research prototype. It is not production hardened. Never submit confidential messages or expose it publicly without authentication, HTTPS, and data-retention protections.
    """)
