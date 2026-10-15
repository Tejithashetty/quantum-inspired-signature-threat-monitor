import streamlit as st

from app.db import initialize_db, recent_events
from app.service import analyze_and_store_event

initialize_db()

st.set_page_config(page_title="Signature Threat Monitor", page_icon="🔐", layout="wide")
st.title("Digital Signature Threat Monitor")
st.caption("Live Ed25519 verification with statistical, ML, and QUBO-style risk analysis.")

input_tab, monitor_tab, about_tab = st.tabs(["Submit live event", "Live monitor", "How detection works"])

with input_tab:
    st.subheader("Submit a signed message")
    st.write("Sign a made-up test message with `python sign_message.py`, then paste the message, public key, and signature below.")
    with st.form("submit_event"):
        message = st.text_area("Message", height=120, max_chars=10000)
        public_key = st.text_input("Ed25519 public key (Base64)", max_chars=200)
        signature = st.text_area("Signature (Base64)", height=80, max_chars=300)
        submitted = st.form_submit_button("Analyze event", type="primary")
    if submitted:
        try:
            result = analyze_and_store_event(message, public_key, signature)
            st.success(f"Event #{result['id']} analyzed — {result['risk_level']} risk, score {result['risk_score']}/100")
            st.json(result)
        except ValueError as error:
            st.error(str(error))


@st.fragment(run_every="5s")
def render_live_monitor():
    st.subheader("Recent live events")
    st.caption("This view refreshes every five seconds. The original message is not stored; a keyed fingerprint is shown.")
    events = [dict(row) for row in recent_events()]
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
                ml_score = event.get("ml_score")
                ml_display = "warming up" if ml_score is None else f"{ml_score:.1f}"
                st.caption(f"Received: {event['received_at']} UTC · ML score: {ml_display} · Threshold: {event.get('adaptive_threshold', 40)}")
    else:
        st.info("No events submitted yet. Use the Submit live event tab or POST /api/events locally.")


with monitor_tab:
    render_live_monitor()

with about_tab:
    st.subheader("Detection pipeline")
    st.markdown("""
    1. **Ed25519 verification** checks message integrity against the supplied public key and signature.
    2. **Feature extraction** measures message size, key event rate, repeated messages, and verification outcome.
    3. **Statistical analysis** uses transparent rules and a robust baseline from real events.
    4. **ML analysis** uses Isolation Forest trained on at least 20 prior valid LOW-risk events from this key. Suspicious events are excluded from training; it reports warming-up status until then.
    5. **Quantum-inspired analysis** scores QUBO-style interactions using classical arithmetic. No quantum computer or quantum advantage is claimed.
    6. **Hybrid scoring and risk classification** combines detector scores and uses an adaptive threshold after enough real history is available.

    This is a local student research prototype. It is not production hardened. Never submit confidential messages or expose it publicly without authentication, HTTPS, and data-retention protections.
    """)
