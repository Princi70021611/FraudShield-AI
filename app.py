
import streamlit as st
import pandas as pd
import joblib
from pathlib import Path
from datetime import datetime

from modules.message_detector import detect_message
from modules.url_scanner import scan_url
from database import init_db, save_scan, get_history, clear_history

# ================= PAGE CONFIG =================

st.set_page_config(
    page_title="FraudShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / "model" / "fraud_model.pkl"
SCALER_PATH = ROOT / "model" / "scaler.pkl"
FEATURES_PATH = ROOT / "model" / "feature_names.pkl"

init_db()

# ================= CUSTOM DESIGN =================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

.stApp {
    background: radial-gradient(ellipse at top left,
    #142d40 0%, #07111f 45%, #050b14 100%);
}
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif;
}
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}
h1, h2, h3 {
    font-family: 'Space Grotesk', sans-serif !important;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1827, #07111c);
    border-right: 1px solid #1b3449;
}
[data-testid="stSidebar"] * {
    color: #e7f2fb;
}
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #142b3e, #0a1928);
    border: 1px solid #244359;
    padding: 16px;
    border-radius: 15px;
}
[data-testid="stMetricLabel"] {
    color: #9ab0c3 !important;
}
[data-testid="stMetricValue"] {
    color: #f3fbff !important;
}
.stButton > button, .stDownloadButton > button {
    border-radius: 10px;
    min-height: 2.6rem;
    font-weight: 700;
    border: 1px solid #2a5267;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(100deg, #42dcb4, #7ef3cf);
    color: #05251f;
    border: 0;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: #53f0c2;
}
hr {
    border-color: #1b3449 !important;
}
.hero {
    padding: 28px;
    border: 1px solid #24506a;
    border-radius: 20px;
    background: linear-gradient(115deg, #10283c, #104044);
    margin-bottom: 22px;
}
.hero .eyebrow {
    color: #53f0c2;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 2px;
}
.hero h1 {
    color: #f5fbff;
    font-size: 2.4rem;
    margin: 8px 0;
}
.hero p {
    color: #b7cad8;
    margin-bottom: 0;
}
.panel {
    padding: 18px;
    border: 1px solid #1b3449;
    border-radius: 15px;
    background: rgba(13, 27, 42, 0.8);
}
.muted {
    color: #9ab0c3;
    font-size: 0.9rem;
}
</style>
""", unsafe_allow_html=True)


def hero(kicker, title, subtitle):
    st.markdown(
        f'<div class="hero">'
        f'<div class="eyebrow">{kicker}</div>'
        f'<h1>{title}</h1><p>{subtitle}</p></div>',
        unsafe_allow_html=True
    )


def show_risk(risk):
    risk = str(risk).lower()

    if risk == "high":
        st.error("🚨 HIGH RISK — warning indicators detected.")
    elif risk == "medium":
        st.warning("⚠️ MEDIUM RISK — review the indicators.")
    elif risk == "unknown":
        st.info("Risk could not be assessed reliably.")
    else:
        st.success(
            "LOW INDICATOR SCORE — this does not guarantee safety."
        )


def show_reasons(reasons):
    if reasons:
        for reason in reasons:
            st.markdown(f"- {reason}")
    else:
        st.write("No configured warning indicators were returned.")


def model_files_available():
    return all(
        path.exists()
        for path in (MODEL_PATH, SCALER_PATH, FEATURES_PATH)
    )


# ================= SIDEBAR =================

with st.sidebar:
    st.markdown("### 🛡️ FraudShield AI")
    st.caption("INTELLIGENT SECURITY WORKSPACE")
    st.divider()

    section = st.radio(
        "NAVIGATION",
        [
            "Dashboard Overview",
            "Message / OTP Scanner",
            "URL Security Scanner",
            "Transaction Risk",
            "ML Prediction",
            "Scan History",
        ],
        key="main_navigation",
    )

    st.divider()
    st.success("Local analysis workspace")
    st.caption("Educational project prototype")
    st.caption(
        "Never enter a real OTP, PIN, password or CVV."
    )


# ================= DASHBOARD =================

if section == "Dashboard Overview":

    hero(
        "SECURITY INTELLIGENCE / 01",
        "Your Digital Safety Center",
        "Analyze suspicious messages, links and transaction patterns "
        "from one professional workspace."
    )

    history = pd.DataFrame(get_history(limit=2000))

    if history.empty:
        total = high = medium = low = 0
    else:
        total = len(history)
        risks = history["risk"].astype(str).str.lower()
        high = int((risks == "high").sum())
        medium = int((risks == "medium").sum())
        low = int((risks == "low").sum())

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Saved Scans", total)
    c2.metric("High-Risk Flags", high)
    c3.metric("Medium-Risk Flags", medium)
    c4.metric(
        "ML Model Files",
        "Ready" if model_files_available() else "Not Found"
    )

    st.write("")
    left, right = st.columns([1.2, 0.8], gap="large")

    with left:
        st.subheader("Security Modules")

        st.markdown("""
        <div class="panel">
        <b>📩 Message / OTP Scanner</b>
        <p class="muted">Detects common scam wording and requests for
        sensitive information.</p>
        <hr>
        <b>🔗 URL Security Scanner</b>
        <p class="muted">Checks URL structure for suspicious indicators
        without opening the website.</p>
        <hr>
        <b>💳 Transaction Risk</b>
        <p class="muted">Reviews sample transaction behavior using
        transparent demonstration rules.</p>
        <hr>
        <b>🤖 ML Prediction</b>
        <p class="muted">Runs the saved model against compatible
        transaction CSV data.</p>
        </div>
        """, unsafe_allow_html=True)

    with right:
        st.subheader("Risk Distribution")

        if total:
            chart = pd.DataFrame({
                "Risk": ["High", "Medium", "Low"],
                "Scans": [high, medium, low],
            }).set_index("Risk")
            st.bar_chart(chart)
        else:
            st.info(
                "Risk charts will appear after you perform your first scan."
            )

        st.markdown("""
        <div class="panel">
        <b>System information</b>
        <p class="muted">Message and URL checks are rule-based.
        Transaction review uses demonstration rules.
        CSV predictions use your saved ML model.</p>
        </div>
        """, unsafe_allow_html=True)

    st.subheader("Recent Activity")

    if history.empty:
        st.info("No scans recorded yet.")
    else:
        st.dataframe(
            history.head(8),
            use_container_width=True,
            hide_index=True
        )

    st.warning(
        "A risk label is not proof of fraud. A low score cannot "
        "guarantee that a message, website or transaction is safe."
    )


# ================= MESSAGE SCANNER =================

elif section == "Message / OTP Scanner":

    hero(
        "MESSAGE INTELLIGENCE / 02",
        "Message & OTP Scanner",
        "Inspect suspicious wording. Use a redacted sample instead "
        "of real personal or financial information."
    )

    message = st.text_area(
        "Message to analyze",
        placeholder=(
            "Example: Your account will be blocked. "
            "Verify immediately using this link..."
        ),
        height=160,
        key="message_input",
    )

    st.caption(
        "Replace names, phone numbers, account numbers and codes "
        "with [REDACTED]."
    )

    if st.button(
        "🔍 Analyze Message",
        type="primary",
        use_container_width=True,
        key="check_message",
    ):
        if not message.strip():
            st.warning("Please enter a sample message.")
        else:
            result = detect_message(message)
            risk = result.get("risk", "Unknown")
            score = result.get("score", 0)
            reasons = result.get("reasons", [])

            show_risk(risk)

            c1, c2 = st.columns(2)
            c1.metric("Risk Level", str(risk))
            c2.metric("Indicator Score", str(score))

            st.subheader("Why was it flagged?")
            show_reasons(reasons)

            # Save only a generic summary, not the message text.
            save_scan(
                "Message / OTP",
                risk,
                score,
                "; ".join(map(str, reasons)),
                "Message content not stored",
            )

            st.caption(
                "This is a rule-based check. Verify suspicious requests "
                "using an official app or a trusted contact method."
            )


# ================= URL SCANNER =================

elif section == "URL Security Scanner":

    hero(
        "LINK INTELLIGENCE / 03",
        "URL Security Scanner",
        "Review a suspicious URL without opening the destination."
    )

    url = st.text_input(
        "URL to inspect",
        placeholder="https://example.com",
        key="url_input",
    )

    st.caption(
        "Paste the URL as text. Do not visit a suspicious link to test it."
    )

    if st.button(
        "🛡️ Scan URL",
        type="primary",
        use_container_width=True,
        key="scan_url_button",
    ):
        if not url.strip():
            st.warning("Please enter a URL.")
        else:
            result = scan_url(url.strip())
            risk = result.get("risk", "Unknown")
            score = result.get("score", 0)
            reasons = result.get("reasons", [])

            show_risk(risk)

            c1, c2 = st.columns(2)
            c1.metric("Risk Level", str(risk))
            c2.metric("Indicator Score", str(score))

            st.subheader("URL Warning Indicators")
            show_reasons(reasons)

            # Store a shortened URL reference, not page contents.
            save_scan(
                "URL Scanner",
                risk,
                score,
                "; ".join(map(str, reasons)),
                url.strip()[:220],
            )

            st.caption(
                "The scanner does not visit the URL. HTTPS alone "
                "does not prove that a website is legitimate."
            )


# ================= TRANSACTION RISK =================

elif section == "Transaction Risk":

    hero(
        "BEHAVIORAL ANALYSIS / 04",
        "Transaction Risk Lab",
        "Explore transaction warning signs using sample behavioral data."
    )

    st.info(
        "This module uses demonstration rules, not the trained ML model. "
        "Its thresholds are examples, not official banking standards."
    )

    with st.form("transaction_form"):
        left, right = st.columns(2)

        with left:
            amount = st.number_input(
                "Transaction Amount (₹)",
                min_value=0.0,
                value=1000.0,
                step=500.0,
            )
            frequency = st.number_input(
                "Transactions in selected period",
                min_value=1,
                max_value=1000,
                value=5,
            )
            location_deviation = st.number_input(
                "Location Deviation (sample score)",
                min_value=0.0,
                value=0.0,
                step=10.0,
            )

        with right:
            transaction_hour = st.slider(
                "Transaction Hour", 0, 23, 12
            )
            merchant = st.selectbox(
                "Merchant Category",
                [
                    "Shopping", "Food", "Travel",
                    "Bills", "Entertainment", "Other"
                ],
            )
            transaction_type = st.selectbox(
                "Transaction Type",
                ["UPI", "Credit Card"],
            )

        submitted = st.form_submit_button(
            "🔍 Review Transaction",
            type="primary",
            use_container_width=True,
        )

   
    if submitted:
        reasons = []
        points = 0

        # 1. Transaction amount
        if amount >= 50000:
            points += 3
            reasons.append(
                "Very high transaction amount (₹50,000 or more)."
            )
        elif amount >= 20000:
            points += 2
            reasons.append(
                "Higher-than-usual transaction amount."
            )
        elif amount >= 10000:
            points += 1
            reasons.append(
                "Moderately high transaction amount."
            )

        # 2. Transaction frequency
        if frequency > 20:
            points += 3
            reasons.append(
                "Unusually high transaction frequency."
            )
        elif frequency > 10:
            points += 2
            reasons.append(
                "Frequent transactions detected."
            )
        elif frequency > 5:
            points += 1
            reasons.append(
                "Transaction frequency is elevated."
            )

        # 3. Location deviation
        if location_deviation > 100:
            points += 3
            reasons.append(
                "Large deviation from the usual location."
            )
        elif location_deviation > 50:
            points += 2
            reasons.append(
                "Unusual transaction location."
            )
        elif location_deviation > 20:
            points += 1
            reasons.append(
                "Moderate location deviation."
            )

        # 4. Transaction time
        if transaction_hour < 5:
            points += 2
            reasons.append(
                "Transaction occurred between midnight and 04:59."
            )

        # Classify the score
        if points >= 6:
            risk = "High"
        elif points >= 3:
            risk = "Medium"
        else:
            risk = "Low"

        risk = (
            "High" if points >= 4
            else "Medium" if points >= 2
            else "Low"
        )

        show_risk(risk)

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Demo Risk Score", f"{points}/7")
        c2.metric("Amount", f"₹{amount:,.2f}")
        c3.metric("Transactions", int(frequency))
        c4.metric("Hour", f"{transaction_hour:02d}:00")

        st.subheader("Rule Explanation")
        show_reasons(reasons)

        st.write(f"**Transaction Type:** {transaction_type}")
        st.write(f"**Merchant Category:** {merchant}")

        if not reasons:
            st.info(
                "No configured rules were triggered. This does not "
                "mean the transaction is verified safe."
            )

        save_scan(
            "Transaction Risk",
            risk,
            points,
            "; ".join(reasons) if reasons else "No configured rules triggered",
            f"{transaction_type}; {merchant}; ₹{amount:.2f}",
        )


# ================= ML PREDICTION =================

elif section == "ML Prediction":

    hero(
        "MODEL WORKSPACE / 05",
        "Machine Learning Prediction",
        "Analyze a CSV using the feature columns expected by your saved model."
    )

    st.warning(
        "Your model was trained on credit-card data. Its predictions "
        "have not been validated for UPI transactions."
    )

    uploaded = st.file_uploader(
        "Upload transaction CSV",
        type=["csv"],
        key="prediction_csv",
    )

    if not model_files_available():
        st.error(
            "Model files are missing. Expected files: "
            "model/fraud_model.pkl, model/scaler.pkl and "
            "model/feature_names.pkl."
        )

    if uploaded is not None and model_files_available():
        try:
            data = pd.read_csv(uploaded)

            if data.empty:
                st.warning("The uploaded CSV has no rows.")
            else:
                model = joblib.load(MODEL_PATH)
                scaler = joblib.load(SCALER_PATH)
                feature_names = joblib.load(FEATURES_PATH)

                missing = [
                    col for col in feature_names
                    if col not in data.columns
                ]

                if missing:
                    st.error(
                        "Required feature columns are missing: "
                        + ", ".join(map(str, missing))
                    )
                else:
                    X = data[list(feature_names)].apply(
                        pd.to_numeric,
                        errors="coerce",
                    )

                    if X.isna().any().any():
                        bad_columns = X.columns[
                            X.isna().any()
                        ].tolist()

                        st.error(
                            "Missing or non-numeric values in: "
                            + ", ".join(map(str, bad_columns))
                        )
                    else:
                        X_scaled = scaler.transform(X)
                        predictions = model.predict(X_scaled)

                        results = data.copy()
                        results["FraudShield Prediction"] = [
                            "Potential Fraud" if int(value) == 1
                            else "Likely Normal"
                            for value in predictions
                        ]

                        has_probability = hasattr(
                            model, "predict_proba"
                        )

                        if has_probability:
                            results[
                                "Estimated Fraud Probability (%)"
                            ] = (
                                model.predict_proba(X_scaled)[:, 1]
                                * 100
                            ).round(2)

                        total = len(predictions)
                        fraud_count = int(
                            (predictions == 1).sum()
                        )
                        normal_count = total - fraud_count

                        st.success("CSV analysis completed.")

                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Rows Analyzed", f"{total:,}")
                        c2.metric("Potential Fraud", f"{fraud_count:,}")
                        c3.metric("Likely Normal", f"{normal_count:,}")
                        c4.metric(
                            "Flagged Share",
                            f"{fraud_count / total * 100:.2f}%"
                        )

                        st.subheader("Prediction Distribution")

                        chart = pd.DataFrame({
                            "Prediction": [
                                "Potential Fraud", "Likely Normal"
                            ],
                            "Transactions": [
                                fraud_count, normal_count
                            ],
                        }).set_index("Prediction")

                        st.bar_chart(chart)

                        if has_probability:
                            st.subheader(
                                "Estimated Fraud Probability"
                            )
                            st.line_chart(
                                results[
                                    "Estimated Fraud Probability (%)"
                                ].reset_index(drop=True)
                            )

                        only_fraud = st.checkbox(
                            "🚨 Show only potential fraud transactions"
                        )

                        display = results
                        if only_fraud:
                            display = results[
                                results["FraudShield Prediction"]
                                == "Potential Fraud"
                            ]

                        st.caption(
                            f"Showing {min(100, len(display)):,} of "
                            f"{len(display):,} matching rows."
                        )

                        st.dataframe(
                            display.head(100),
                            use_container_width=True,
                            hide_index=True,
                        )

                        st.download_button(
                            "⬇️ Download Prediction Report",
                            data=results.to_csv(
                                index=False
                            ).encode("utf-8-sig"),
                            file_name="fraudshield_predictions.csv",
                            mime="text/csv",
                            use_container_width=True,
                        )

        except Exception as exc:
            st.error(f"Could not process the CSV: {exc}")
            st.caption(
                "Check that the file is valid and its feature columns "
                "match the model's training data."
            )


# ================= SCAN HISTORY =================

elif section == "Scan History":

    hero(
        "AUDIT TRAIL / 06",
        "Scan History",
        "Review saved scan summaries and export your local report."
    )

    history = pd.DataFrame(get_history(limit=2000))

    if history.empty:
        st.info(
            "No saved history yet. Run a message, URL or transaction scan."
        )
    else:
        c1, c2 = st.columns(2)

        tool_options = ["All"] + sorted(
            history["tool"].dropna().astype(str).unique().tolist()
        )
        risk_options = ["All"] + sorted(
            history["risk"].dropna().astype(str).unique().tolist()
        )

        selected_tool = c1.selectbox(
            "Filter by tool", tool_options
        )
        selected_risk = c2.selectbox(
            "Filter by risk", risk_options
        )

        filtered = history.copy()

        if selected_tool != "All":
            filtered = filtered[
                filtered["tool"] == selected_tool
            ]

        if selected_risk != "All":
            filtered = filtered[
                filtered["risk"] == selected_risk
            ]

        st.caption(
            f"{len(filtered):,} records match your filters."
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "⬇️ Export Scan History",
            data=filtered.to_csv(
                index=False
            ).encode("utf-8-sig"),
            file_name="fraudshield_scan_history.csv",
            mime="text/csv",
        )

        with st.expander("Clear saved history"):
            st.warning(
                "This permanently deletes saved scan history records."
            )

            confirm = st.checkbox(
                "I understand and want to clear history."
            )

            if st.button(
                "Clear History",
                disabled=not confirm,
            ):
                clear_history()
                st.success("History cleared.")
                st.rerun()


# ================= FOOTER =================

st.divider()

left, right = st.columns([3, 1])

with left:
    st.caption(
        "🛡️ FraudShield AI | Intelligent Fraud Detection Project"
    )

with right:
    st.caption(datetime.now().strftime("%d %b %Y"))
