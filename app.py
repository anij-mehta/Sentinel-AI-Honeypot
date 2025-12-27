import streamlit as st
import pandas as pd
import json
import altair as alt 
from sklearn.ensemble import IsolationForest

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="Sentinel-AI: Final Report", layout="wide")
st.title("🛡️ Sentinel-AI: Zero-Day Threat Detection System")

# --- DATA LOADING ---
@st.cache_data
def load_data():
    data = []
    try:
        with open('attacks.json', 'r') as f:
            for line in f:
                data.append(json.loads(line))
    except FileNotFoundError:
        st.error("Data file missing. Run fetch_live_data.py!")
        return pd.DataFrame()
    return pd.DataFrame(data)

df = load_data()

if not df.empty:
    # 1. Feature Engineering
    sessions = df.groupby('session').agg(
        start_time=('timestamp', 'min'),
        end_time=('timestamp', 'max'),
        src_ip=('src_ip', 'first'),
        total_events=('eventid', 'count'),
        unique_commands=('input', 'nunique'),
        has_wget=('input', lambda x: 1 if x.str.contains('wget|curl', na=False).any() else 0)
    ).reset_index()

    # 2. Duration Calculation
    sessions['start_time'] = pd.to_datetime(sessions['start_time'])
    sessions['end_time'] = pd.to_datetime(sessions['end_time'])
    sessions['duration'] = (sessions['end_time'] - sessions['start_time']).dt.total_seconds()
    
    # 3. CRITICAL: Force Data Types & Handle Zeros
    sessions['duration'] = sessions['duration'].fillna(0.1).astype(float)
    sessions['duration'] = sessions['duration'].apply(lambda x: max(x, 0.1))
    sessions['unique_commands'] = sessions['unique_commands'].fillna(0).astype(int)

    # --- MACHINE LEARNING ---
    features = ['duration', 'unique_commands', 'total_events']
    X = sessions[features]
    
    # Isolation Forest
    model = IsolationForest(contamination=0.04, random_state=42)
    sessions['anomaly_score'] = model.fit_predict(X)
    
    # Label Results
    sessions['threat_type'] = sessions['anomaly_score'].apply(lambda x: "🚨 High-Risk Anomaly" if x == -1 else "🤖 Automated Bot")

    # --- DASHBOARD LAYOUT ---
    
    k1, k2, k3 = st.columns(3)
    k1.metric("Total Sessions Analyzed", len(sessions))
    k2.metric("Threats Detected", len(sessions[sessions['threat_type'].str.contains("Anomaly")]))
    k3.metric("System Status", "⚡ Active Protection Enabled")

    col1, col2 = st.columns([3, 1])

    with col1:
        st.subheader("🔍 Behavioral Analysis (Isolation Forest)")
        
        # --- VISUALIZATION ---
        
        chart = alt.Chart(sessions).mark_circle(size=100).encode(
            x=alt.X('duration', title='Session Duration (Seconds)', scale=alt.Scale(type='symlog')), # Log scale to see both fast and slow attacks
            y=alt.Y('unique_commands', title='Unique Commands Executed'),
            color=alt.Color('threat_type', 
                            scale=alt.Scale(domain=['🚨 High-Risk Anomaly', '🤖 Automated Bot'], 
                                            range=['red', 'blue']),
                            legend=alt.Legend(title="Classification")),
            tooltip=['src_ip', 'duration', 'unique_commands', 'threat_type']
        ).properties(
            height=400
        ).interactive() # zoomable/pannable
        
        st.altair_chart(chart, use_container_width=True)

    with col2:
        st.subheader("🚨 Live Alerts")
        anomalies = sessions[sessions['threat_type'].str.contains("Anomaly")]
        if not anomalies.empty:
            st.dataframe(
                anomalies[['src_ip', 'duration', 'unique_commands']],
                hide_index=True
            )
        else:
            st.success("No active threats detected.")

    # --- EXPORT SECTION ---
    st.divider()
    st.subheader("📂 Forensic Log Data")
    st.dataframe(sessions.sort_values(by='start_time', ascending=False).head(10))

else:
    st.warning("Waiting for data synchronization...")