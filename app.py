import hashlib
import time
from datetime import datetime
import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
import requests

# ==============================================================================
# PAGE CONFIGURATION & GLOBAL STYLES
# ==============================================================================
st.set_page_config(
    page_title="AQUAGUARD — Leak Detection & Accountability Engine",
    page_icon="💧",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .stApp {
        background-color: #030712;
        color: #f3f4f6;
        font-family: 'Inter', sans-serif;
    }
    .aqua-header {
        background-color: #0b1329;
        border: 1px solid #1e293b;
        border-radius: 1rem;
        padding: 1.25rem;
        margin-bottom: 1.25rem;
        box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
    }
    .badge-nirvaan {
        background-color: rgba(8, 145, 178, 0.2);
        color: #38bdf8;
        border: 1px solid #075985;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: monospace;
    }
    .badge-team {
        background-color: #1e293b;
        color: #cbd5e1;
        border: 1px solid #334155;
        padding: 0.2rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .banner-alarm {
        background-color: rgba(69, 10, 10, 0.6);
        border: 1px solid rgba(239, 68, 68, 0.5);
        border-radius: 1rem;
        padding: 1rem 1.25rem;
        margin-bottom: 1.25rem;
    }
    .node-card {
        background-color: #0b1329;
        border: 1px solid #1e293b;
        border-radius: 1rem;
        padding: 1rem;
    }
    .node-card-danger {
        background-color: #0b1329;
        border: 1px solid rgba(220, 38, 38, 0.5);
        border-radius: 1rem;
        padding: 1rem;
        box-shadow: 0 4px 15px -1px rgba(220, 38, 38, 0.2);
    }
    .stage-box {
        padding: 0.6rem 0.8rem;
        border-radius: 0.75rem;
        font-size: 0.85rem;
        margin-bottom: 0.5rem;
        border: 1px solid #1e293b;
        background-color: #030712;
    }
    .stage-active {
        background-color: rgba(245, 158, 11, 0.15);
        border: 1px solid #f59e0b;
        color: #fef3c7;
    }
    .stage-reopened {
        background-color: rgba(239, 68, 68, 0.2);
        border: 1px solid #ef4444;
        color: #fecdd3;
    }
    .stage-verifying {
        background-color: rgba(6, 182, 212, 0.2);
        border: 1px solid #06b6d4;
        color: #cff4fc;
    }
    .hash-log-item {
        background-color: #030712;
        border: 1px solid #1e293b;
        border-radius: 0.5rem;
        padding: 0.5rem 0.75rem;
        margin-bottom: 0.4rem;
        font-size: 0.75rem;
    }
    .role-card {
        background-color: #0b1329;
        border: 1px solid #1e293b;
        border-radius: 1rem;
        padding: 1.25rem;
        margin-bottom: 1rem;
    }
    .ticket-badge {
        font-family: monospace;
        font-size: 0.75rem;
        padding: 0.25rem 0.5rem;
        border-radius: 0.375rem;
        font-weight: bold;
    }
    .status-open { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .status-assigned { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .status-progress { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    .status-fixed { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# HELPER FUNCTIONS & SHA-256 AUDIT ENGINE
# ==============================================================================
def create_hash(event_text, previous_hash=""):
    payload = f"{event_text}|{previous_hash}|{datetime.now().isoformat()}"
    return "0x" + hashlib.sha256(payload.encode()).hexdigest()[:14]

def log_audit_event(event_text):
    prev_hash = st.session_state.audit_chain[0]["hash"] if st.session_state.audit_chain else "0x00000000000000"
    new_hash = create_hash(event_text, prev_hash)
    st.session_state.audit_chain.insert(0, {
        "event": event_text,
        "hash": new_hash,
        "time": datetime.now().strftime("%I:%M:%S %p")
    })

# ==============================================================================
# INITIALIZE SESSION STATE & NETWORK CONFIG
# ==============================================================================
if "app_role" not in st.session_state:
    st.session_state.app_role = "🏛️ Municipality Web Portal"

if "use_live_esp32" not in st.session_state:
    st.session_state.use_live_esp32 = False

if "esp32_ip" not in st.session_state:
    st.session_state.esp32_ip = "192.168.1.50"

if "incident_state" not in st.session_state:
    st.session_state.incident_state = "ESCALATED" # ESCALATED, VERIFYING, REOPENED, RESOLVED
    st.session_state.confidence_score = 88
    
    # Audit Chain
    initial_chain = []
    h1 = create_hash("ESP32 #2 (Sensor S3) registered 72.1 L/min usage")
    h2 = create_hash("Flow Imbalance calculated (38.4 L/min loss on Sensor S2 branch)", h1)
    h3 = create_hash("Confidence score reached 88% (>80% threshold)", h2)
    h4 = create_hash("Auto-Escalation triggered: DMA Zone 4 Authority Alerted", h3)
    
    initial_chain.append({"event": "Auto-Escalation triggered: DMA Zone 4 Authority Alerted", "hash": h4, "time": "10:15:45 AM"})
    initial_chain.append({"event": "Confidence score reached 88% (>80% threshold)", "hash": h3, "time": "10:15:30 AM"})
    initial_chain.append({"event": "Flow Imbalance calculated (38.4 L/min loss on Sensor S2 branch)", "hash": h2, "time": "10:15:18 AM"})
    initial_chain.append({"event": "ESP32 #2 (Sensor S3) registered 72.1 L/min usage", "hash": h1, "time": "10:15:02 AM"})
    st.session_state.audit_chain = initial_chain

# Role 1: Citizen Tickets DB
if "citizen_tickets" not in st.session_state:
    st.session_state.citizen_tickets = [
        {
            "id": "TCK-8042",
            "locality": "DMA Zone 4 — Sector 7 Main Rd",
            "severity": "Major Burst",
            "status": "Assigned", # Reported, Assigned, Fixed, Closed, Reopened
            "crew": "Crew Alpha (Nordic Hydro)",
            "eta": "2 Hours",
            "reported_time": "10:14 AM",
            "details": "Heavy water burst near junction valve. Flowing onto road.",
            "dispute_count": 0
        }
    ]

# Role 2: Crew Assignments DB
if "crew_tasks" not in st.session_state:
    st.session_state.crew_tasks = [
        {
            "id": "TCK-8042",
            "zone": "Zone 4 - Sec 7",
            "assigned_by": "Municipal Admin",
            "status": "Accepted", # Pending, Accepted, Progress, Repair Filed
            "eta": "2 Hours",
            "pipe_spec": "350mm PVC Distribution Line",
            "notes": "Valve Leak A requires replacement packing."
        }
    ]

# ==============================================================================
# HARDWARE TELEMETRY ENGINE (LIVE ESP32 HTTP POLLING / SIMULATION FALLBACK)
# ==============================================================================
def fetch_esp32_telemetry():
    if st.session_state.use_live_esp32:
        try:
            url = f"http://{st.session_state.esp32_ip}/data"
            response = requests.get(url, timeout=1.5)
            if response.status_code == 200:
                data = response.json()
                # Expecting JSON format: {"s1": 120.5, "s2": 10.0, "s3": 72.1}
                s1 = round(float(data.get("s1", 120.5)), 1)
                s2 = round(float(data.get("s2", 10.0)), 1)
                s3 = round(float(data.get("s3", 72.1)), 1)
                return s1, s2, s3, True
        except Exception:
            pass

    # Simulation Fallback
    np.random.seed(int(time.time()) % 1000)
    noise1 = (np.random.rand() - 0.5) * 0.4
    noise2 = (np.random.rand() - 0.5) * 0.4
    s1 = round(120.5 + noise1, 1) # S1 Input
    s3 = round(72.1 + noise2, 1)  # S3 Left Branch
    s2 = round(10.0 + noise2, 1)  # S2 Right Branch
    return s1, s2, s3, False

node1_flow, node3_flow, node2_flow, is_hardware_live = fetch_esp32_telemetry()
unaccounted_loss = round(node1_flow - node2_flow - node3_flow, 1)

# ==============================================================================
# SIDEBAR CONTROL PANEL & INTERFACE SWITCHER
# ==============================================================================
st.sidebar.markdown("### ⚙️ AQUAGUARD Navigation")

st.session_state.app_role = st.sidebar.radio(
    "Select Active Interface Role:",
    [
        "🏛️ Municipality Web Portal",
        "👨‍👩‍👧 Local Citizen Mobile App",
        "🛠️ Repair Crew Ground App",
        "📡 IoT Hardware Telemetry Dashboard"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 🌐 ESP32 Hardware Connection")
st.session_state.use_live_esp32 = st.sidebar.checkbox("Connect Live ESP32 Hardware", value=st.session_state.use_live_esp32)

if st.session_state.use_live_esp32:
    st.session_state.esp32_ip = st.sidebar.text_input("ESP32 Shared IP Address", value=st.session_state.esp32_ip)
    if is_hardware_live:
        st.sidebar.success("✅ Connected to ESP32 Network!")
    else:
        st.sidebar.warning("⚠️ Reading from Shared IP failed. Running simulation fallback.")

st.sidebar.markdown("---")
st.sidebar.markdown("### 🎛️ Live Simulation Controls")

if st.sidebar.button("🔄 Trigger Data Telemetry Refresh", use_container_width=True):
    st.rerun()

st.sidebar.caption("SIH Project Phase — Team Jal Lijiye (Nirvaan Architecture)")

# ==============================================================================
# HEADER BANNER (PERMANENT ACROSS ALL VIEWS)
# ==============================================================================
st.markdown(f"""
<div class="aqua-header">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
        <div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
                <h1 style="margin: 0; font-size: 1.8rem; font-weight: 800; background: linear-gradient(to right, #22d3ee, #38bdf8, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                    💧 AQUAGUARD
                </h1>
                <span class="badge-nirvaan">Nirvaan</span>
                <span class="badge-team">Team Jal Lijiye</span>
            </div>
            <p style="margin: 0.25rem 0 0 0; font-size: 0.8rem; color: #94a3b8;">
                Multi-Role Water Leakage Governance & Physical Telemetry Accountability Network — DMA Zone 4
            </p>
        </div>
        <div style="display: flex; align-items: center; gap: 0.75rem;">
            <span style="font-family: monospace; font-size: 0.75rem; color: #38bdf8; background: #0f172a; padding: 0.3rem 0.7rem; border-radius: 0.5rem; border: 1px solid #1e293b;">
                Active Interface: <b>{st.session_state.app_role.split(' ')[1]}</b>
            </span>
            <span style="font-family: monospace; font-size: 0.75rem; color: {'#34d399' if is_hardware_live else '#fbbf24'}; background: {'#064e3b' if is_hardware_live else '#451a03'}; padding: 0.3rem 0.7rem; border-radius: 0.5rem; border: 1px solid {'#065f46' if is_hardware_live else '#78350f'};">
                ● {'LIVE HARDWARE' if is_hardware_live else '3/3 ESP32 SIMULATED'}
            </span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# ==============================================================================
# INTERFACE 1: MUNICIPALITY WEB PORTAL
# ==============================================================================
if st.session_state.app_role == "🏛️ Municipality Web Portal":
    st.subheader("🏛️ Municipality Command & Control Center")
    st.caption("Receive citizen complaints, triage ground IoT alerts, dispatch repair crews, and verify physical fixes.")

    col1, col2 = st.columns([7, 5])

    with col1:
        st.markdown("##### 📋 Active Zone Leakage Incident Queue")
        
        for tck in st.session_state.citizen_tickets:
            status_class = f"status-{tck['status'].lower()}"
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{tck['id']}</span>
                    <span class="ticket-badge {status_class}">{tck['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: 700; margin-top: 0.4rem; color: #f3f4f6;">📍 {tck['locality']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">{tck['details']}</div>
                <div style="font-size: 0.75rem; color: #64748b; margin-top: 0.5rem; font-family: monospace;">
                    Reported: {tck['reported_time']} | Severity: {tck['severity']} | Disputed Re-opens: {tck['dispute_count']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Interactive Municipal Actions
            c_act1, c_act2, c_act3 = st.columns(3)
            with c_act1:
                if tck['status'] == "Reported":
                    if st.button("🚀 Dispatch Crew Alpha", key="muni_dispatch"):
                        tck['status'] = "Assigned"
                        tck['crew'] = "Crew Alpha"
                        log_audit_event(f"Municipality dispatched Crew Alpha to Ticket {tck['id']}")
                        st.success("Repair Crew Dispatched!")
                        st.rerun()
            
            with c_act2:
                if tck['status'] in ["Fixed", "Repair Filed"]:
                    if st.button("🔍 Verify Physics & Close", key="muni_verify"):
                        # Check physical sensors
                        if unaccounted_loss > 5.0:
                            tck['status'] = "Reopened"
                            tck['dispute_count'] += 1
                            st.session_state.incident_state = "REOPENED"
                            log_audit_event(f"🚨 Municipal Inspection FAILED for {tck['id']}! Sensor loss ({unaccounted_loss} L/min) persists. Ticket REOPENED.")
                            st.error("False Repair Detected by ESP32 sensors! Ticket auto-reopened.")
                        else:
                            tck['status'] = "Closed"
                            st.session_state.incident_state = "RESOLVED"
                            log_audit_event(f"✅ Municipal Admin verified repair for {tck['id']}. Ticket formally CLOSED.")
                            st.success("Repair verified by hardware. Case Closed!")
                        st.rerun()

            with c_act3:
                if tck['status'] == "Reopened":
                    st.warning("⚠️ High Priority Escalation Active!")

    with col2:
        st.markdown("##### 🛰️ Cross-Verification Dashboard")
        st.write("Cross-checking ground citizen reports against hardware telemetry.")
        
        st.markdown(f"""
        <div class="role-card">
            <div style="font-size: 0.85rem; color: #cbd5e1; font-weight: 600;">Hardware Telemetry Correlation</div>
            <div style="font-size: 1.4rem; font-weight: 800; color: #ef4444; margin: 0.4rem 0; font-family: monospace;">
                {unaccounted_loss} L/min Loss
            </div>
            <div style="font-size: 0.75rem; color: #94a3b8;">
                Correlated with <b>Ticket #8042</b> (Sector 7 Main Line).
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("##### 🔗 Real-Time Audit Log")
        for item in st.session_state.audit_chain[:3]:
            st.markdown(f"""
            <div class="hash-log-item">
                <div style="color: #e2e8f0; font-weight: 600;">{item['event']}</div>
                <div style="color: #06b6d4; font-family: monospace; font-size: 0.7rem; margin-top: 0.2rem;">
                    Hash: {item['hash']} | {item['time']}
                </div>
            </div>
            """, unsafe_allow_html=True)

# ==============================================================================
# INTERFACE 2: LOCAL CITIZEN MOBILE APP
# ==============================================================================
elif st.session_state.app_role == "👨‍👩‍👧 Local Citizen Mobile App":
    st.subheader("👨‍👩‍👧 Citizen Reporting & Accountability Interface")
    st.caption("Report water leakage, monitor real-time repair progress, and confirm or dispute resolution claims.")

    c_left, c_right = st.columns([6, 6])

    with c_left:
        st.markdown("##### 📢 Report Leakage in Your Locality")
        with st.form("citizen_report_form"):
            loc = st.text_input("Locality / Landmark", value="DMA Zone 4 — Sector 7 Near Water Tank")
            sev = st.selectbox("Severity Level", ["Minor Seepage", "Moderate Leakage", "Major Pipe Burst"])
            desc = st.text_area("Leakage Details", "Water gusher on main road causing heavy loss.")
            submitted = st.form_submit_button("🚨 Submit Leakage Report")
            
            if submitted:
                new_id = f"TCK-{np.random.randint(1000, 9999)}"
                st.session_state.citizen_tickets.append({
                    "id": new_id,
                    "locality": loc,
                    "severity": sev,
                    "status": "Reported",
                    "crew": "Unassigned",
                    "eta": "Awaiting Triage",
                    "reported_time": datetime.now().strftime("%I:%M %p"),
                    "details": desc,
                    "dispute_count": 0
                })
                log_audit_event(f"Citizen submitted leak report {new_id} at {loc}")
                st.success(f"Report Submitted Successfully! Tracking ID: {new_id}")
                st.rerun()

    with c_right:
        st.markdown("##### 📱 Your Active Ticket Tracking")
        for tck in st.session_state.citizen_tickets:
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{tck['id']}</span>
                    <span class="ticket-badge status-{tck['status'].lower()}">{tck['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: bold; margin-top: 0.4rem;">{tck['locality']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">Assigned Crew: <b>{tck['crew']}</b></div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Est. Resolution Time: <b>{tck['eta']}</b></div>
            </div>
            """, unsafe_allow_html=True)

            # Dispute / Reopen Mechanism
            if tck['status'] in ["Fixed", "Closed", "Repair Filed"]:
                st.warning("Municipality / Crew has marked this repair as complete.")
                col_disp1, col_disp2 = st.columns(2)
                with col_disp1:
                    if st.button("✅ Confirm Water Fixed", key=f"confirm_{tck['id']}"):
                        tck['status'] = "Closed"
                        log_audit_event(f"Citizen confirmed resolution for ticket {tck['id']}.")
                        st.success("Thank you for confirming!")
                        st.rerun()
                with col_disp2:
                    if st.button("🚨 Report False Repair (Reopen)", key=f"dispute_{tck['id']}"):
                        tck['status'] = "Reopened"
                        tck['dispute_count'] += 1
                        st.session_state.incident_state = "REOPENED"
                        log_audit_event(f"🚨 CITIZEN DISPUTE! Citizen reported FALSE REPAIR on {tck['id']}. Ticket re-escalated.")
                        st.error("Ticket re-opened and flagged for priority municipal audit!")
                        st.rerun()

# ==============================================================================
# INTERFACE 3: REPAIR CREW GROUND APP
# ==============================================================================
elif st.session_state.app_role == "🛠️ Repair Crew Ground App":
    st.subheader("🛠️ Ground Repair Crew Mobile Portal")
    st.caption("Accept repair assignments, post status updates, log physical repairs, and estimate resolution times.")

    col_crew1, col_crew2 = st.columns([6, 6])

    with col_crew1:
        st.markdown("##### 👷 Active Task Assignments")
        for task in st.session_state.crew_tasks:
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{task['id']}</span>
                    <span class="ticket-badge status-assigned">{task['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: bold; margin-top: 0.4rem;">Location: {task['zone']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">Pipeline Spec: {task['pipe_spec']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Task Notes: {task['notes']}</div>
            </div>
            """, unsafe_allow_html=True)

            if task['status'] == "Pending":
                if st.button("✅ Accept Task Assignment", key="accept_task"):
                    task['status'] = "Accepted"
                    log_audit_event(f"Repair Crew accepted task assignment {task['id']}")
                    st.success("Task accepted!")
                    st.rerun()

    with col_crew2:
        st.markdown("##### 📝 Submit Repair Status Update")
        with st.form("crew_update_form"):
            t_id = st.selectbox("Select Task Ticket", [t['id'] for t in st.session_state.crew_tasks])
            c_status = st.selectbox("Work Progress", ["In Progress", "Parts Replaced - Testing", "Repair Complete"])
            eta_update = st.text_input("Estimated Fix Completion", "45 Minutes")
            work_notes = st.text_area("Ground Repair Log", "Replaced worn gasket on Leak A Valve. Closed emergency bypass.")
            
            submit_work = st.form_submit_button("📤 Submit Repair Log")
            
            if submit_work:
                # Update task and citizen DB
                for t in st.session_state.crew_tasks:
                    if t['id'] == t_id:
                        t['status'] = c_status
                for c in st.session_state.citizen_tickets:
                    if c['id'] == t_id:
                        c['status'] = "Fixed" if c_status == "Repair Complete" else "In Progress"
                        c['eta'] = eta_update
                
                log_audit_event(f"Crew logged work status '{c_status}' for ticket {t_id}")
                st.success("Repair status logged and transmitted to Municipality & Citizen!")
                st.rerun()

# ==============================================================================
# INTERFACE 4: ORIGINAL IOT HARDWARE TELEMETRY DASHBOARD
# ==============================================================================
else:
    if st.session_state.incident_state == "REOPENED":
        banner_title = "🚨 CRITICAL INCIDENT #8042 — FALSE REPAIR CAUGHT!"
        banner_desc = f"<strong>Accountability Guard Triggered!</strong> Claimed repair rejected. Unaccounted flow loss of <span style='color: #ef4444; font-family: monospace; font-weight: bold;'>{unaccounted_loss} L/min</span> detected on Valve Leak A."
        stage_label = "4. REOPENED (FALSE REPAIR)"
        stage_color = "#ef4444"
    elif st.session_state.incident_state == "VERIFYING":
        banner_title = "⚡ INCIDENT #8042 — REPAIR VERIFICATION IN PROGRESS"
        banner_desc = "Polling ESP32 physics sensors (S1, S2, S3) to verify repair claim..."
        stage_label = "4. VERIFYING SENSOR PHYSICS..."
        stage_color = "#22d3ee"
    elif st.session_state.incident_state == "RESOLVED":
        banner_title = "✅ INCIDENT #8042 — LEAK SUCCESSFULLY RESOLVED"
        banner_desc = "Physical flow balance restored across S1, S2, and S3 sensors."
        stage_label = "5. CLOSED & VERIFIED"
        stage_color = "#34d399"
    else:
        banner_title = "⚠️ CRITICAL INCIDENT #8042 — LEAK DETECTED"
        banner_desc = f"Unaccounted Flow Loss Detected: <span style='color: #ef4444; font-family: monospace; font-weight: bold;'>{unaccounted_loss} L/min</span> (Confidence Score: <span style='font-family: monospace; font-weight: bold; color: #ef4444;'>{st.session_state.confidence_score}%</span>)"
        stage_label = "3. AUTO-ESCALATED"
        stage_color = "#f59e0b"

    st.markdown(f"""
    <div class="banner-alarm">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
            <div>
                <div style="font-size: 0.9rem; font-weight: 700; color: #fecdd3;">{banner_title}</div>
                <div style="font-size: 0.8rem; color: #e2e8f0; margin-top: 0.2rem;">{banner_desc}</div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.65rem; color: #94a3b8; font-family: monospace; text-transform: uppercase;">Lifecycle Stage</div>
                <div style="font-size: 0.85rem; font-weight: 800; font-family: monospace; color: {stage_color};">{stage_label}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_left, col_right = st.columns([7, 4])

    with col_left:
        st.markdown("##### 📡 Live ESP32 Hardware Telemetry Nodes")
        n_col1, n_col2, n_col3 = st.columns(3)
        
        with n_col1:
            st.markdown(f"""
            <div class="node-card">
                <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #38bdf8; font-family: monospace;">
                    <span>ESP32 #1 — S1 INPUT</span>
                    <span style="color: #34d399;">NODE-01</span>
                </div>
                <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Main Input Supply</div>
                <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #38bdf8; margin: 0.4rem 0;">
                    {node1_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                </div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: monospace;">Pressure: 2.41 Bar</div>
            </div>
            """, unsafe_allow_html=True)
            
        with n_col2:
            st.markdown(f"""
            <div class="node-card">
                <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #38bdf8; font-family: monospace;">
                    <span>ESP32 #2 — S3 LEFT</span>
                    <span style="color: #38bdf8;">NODE-02</span>
                </div>
                <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Distribution Node A</div>
                <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #22d3ee; margin: 0.4rem 0;">
                    {node2_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                </div>
                <div style="font-size: 0.7rem; color: #94a3b8; font-family: monospace;">Leak B Valve: CLOSED</div>
            </div>
            """, unsafe_allow_html=True)
            
        with n_col3:
            st.markdown(f"""
            <div class="node-card-danger">
                <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #f87171; font-family: monospace;">
                    <span>ESP32 #3 — S2 RIGHT</span>
                    <span style="color: #f87171;">NODE-03</span>
                </div>
                <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Distribution Node B</div>
                <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #ef4444; margin: 0.4rem 0;">
                    {node3_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                </div>
                <div style="font-size: 0.7rem; color: #f87171; font-family: monospace;">Leak A Valve: ACTIVE</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("##### 🛠️ Hardware Pipeline Setup (Matching Rig Sketch)")
        
        pipeline_html = f"""
    <div style="background-color: #0b1329; border: 1px solid #1e293b; border-radius: 1rem; padding: 1.25rem; margin-bottom: 1rem; text-align: center;">
    <div style="font-size: 0.85rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem;">
    📐 Pipeline Topology (3 Sensors + 2 Simulation Leak Valves)
    </div>

    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; padding: 1rem 0;">

    <div style="display: flex; flex-direction: column; align-items: center; margin-bottom: 0.5rem;">
    <span style="font-size: 0.75rem; font-weight: bold; color: #22d3ee; font-family: monospace;">⬇ MAIN INPUT WATER SUPPLY</span>
    <div style="width: 12px; height: 35px; background: linear-gradient(180deg, #0284c7, #38bdf8); border: 1px solid #0284c7; border-radius: 4px;"></div>
    <div style="background: #0f172a; border: 2px solid #38bdf8; padding: 0.4rem 0.8rem; border-radius: 0.5rem; color: #38bdf8; font-weight: bold; font-family: monospace; font-size: 0.8rem; box-shadow: 0 0 10px rgba(56, 189, 248, 0.3);">
    Sensor S1 (Input): {node1_flow} L/min
    </div>
    <div style="width: 12px; height: 25px; background: linear-gradient(180deg, #38bdf8, #0284c7); border: 1px solid #0284c7;"></div>
    </div>

    <div style="position: relative; width: 85%; max-width: 520px; display: flex; justify-content: space-between; align-items: flex-start;">
    <div style="position: absolute; top: 0; left: 0; right: 0; height: 12px; background: linear-gradient(90deg, #0284c7, #22d3ee, #0284c7); border: 1px solid #0284c7; border-radius: 6px; z-index: 1;"></div>

    <div style="display: flex; flex-direction: column; align-items: center; width: 45%; padding-top: 15px; position: relative; z-index: 2;">
    <div style="font-size: 0.7rem; color: #94a3b8; font-family: monospace; margin-bottom: 0.2rem;">Left Branch</div>
    <div style="background: #030712; border: 1px solid #06b6d4; padding: 0.3rem 0.6rem; border-radius: 0.4rem; color: #22d3ee; font-family: monospace; font-size: 0.75rem; margin-bottom: 0.5rem;">
    Sensor S3: {node2_flow} L/min
    </div>
    <div style="background: #1e1b4b; border: 1px dashed #6366f1; padding: 0.3rem 0.5rem; border-radius: 0.4rem; color: #a5b4fc; font-size: 0.7rem; font-family: monospace; margin-bottom: 0.4rem;">
    🚰 Valve Leak B (Closed)
    </div>
    <div style="width: 10px; height: 20px; background: #0284c7;"></div>
    <span style="font-size: 0.7rem; font-weight: bold; color: #22d3ee; font-family: monospace;">Outlet B ↴</span>
    </div>

    <div style="display: flex; flex-direction: column; align-items: center; width: 45%; padding-top: 15px; position: relative; z-index: 2;">
    <div style="font-size: 0.7rem; color: #f87171; font-family: monospace; margin-bottom: 0.2rem;">Right Branch (Active Leak)</div>
    <div style="background: #450a0a; border: 1px solid #ef4444; padding: 0.3rem 0.5rem; border-radius: 0.4rem; color: #f87171; font-size: 0.7rem; font-weight: bold; font-family: monospace; margin-bottom: 0.5rem; box-shadow: 0 0 8px rgba(239, 68, 68, 0.4);">
    💥 Valve Leak A (OPEN: -{unaccounted_loss} L/min)
    </div>
    <div style="background: #030712; border: 1px solid #ef4444; padding: 0.3rem 0.6rem; border-radius: 0.4rem; color: #ef4444; font-family: monospace; font-size: 0.75rem; margin-bottom: 0.4rem;">
    Sensor S2: {node3_flow} L/min
    </div>
    <div style="width: 10px; height: 20px; background: #991b1b;"></div>
    <span style="font-size: 0.7rem; font-weight: bold; color: #ef4444; font-family: monospace;">Outlet A ↴</span>
    </div>

    </div>

    </div>

    <div style="margin-top: 0.8rem; padding-top: 0.8rem; border-top: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; font-family: monospace; font-size: 0.75rem;">
    <span style="color: #cbd5e1;">Hardware Fusion Rule: Unaccounted Loss = S1 - (S2 + S3)</span>
    <span style="background: #450a0a; color: #f87171; padding: 0.2rem 0.6rem; border-radius: 0.4rem; font-weight: bold; border: 1px solid #7f1d1d;">
    Unaccounted Loss = {unaccounted_loss} L/min
    </span>
    </div>
    </div>
    """
        st.markdown(pipeline_html, unsafe_allow_html=True)

        st.markdown("##### 📈 Real-Time Flow Comparison Telemetry")
        times = [f"10:{10+i:02d}" for i in range(10)]
        e1_data = [120.0 + np.random.normal(0, 0.3) for _ in range(10)]
        e2_data = [72.0 + np.random.normal(0, 0.3) for _ in range(10)]
        e3_data = [48.0, 48.2, 48.1, 10.0, 10.2, 9.9, 10.1, 10.0, 10.1, node3_flow]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=times, y=e1_data, mode='lines+markers', name='S1 Input Supply', line=dict(color='#38bdf8', width=2)))
        fig.add_trace(go.Scatter(x=times, y=e2_data, mode='lines+markers', name='S3 Left Branch', line=dict(color='#22d3ee', width=2)))
        fig.add_trace(go.Scatter(x=times, y=e3_data, mode='lines+markers', name='S2 Right Branch', line=dict(color='#ef4444', width=2)))
        
        fig.update_layout(
            template='plotly_dark',
            paper_bgcolor='#0b1329',
            plot_bgcolor='#030712',
            margin=dict(l=20, r=20, t=30, b=20),
            height=260,
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_right:
        st.markdown("##### 🔄 5-Stage Lifecycle Tracker")
        
        stages = [
            ("1. DETECT", "Anomaly Passed Threshold", "green"),
            ("2. LOCATE", "Right Branch (Leak A) Isolated", "green"),
            ("3. ESCALATE", f"Confidence: {st.session_state.confidence_score}%", "amber"),
            ("4. VERIFY", "Polling Physics" if st.session_state.incident_state == "VERIFYING" else ("Verification FAILED" if st.session_state.incident_state == "REOPENED" else "Awaiting Operator"), "cyan" if st.session_state.incident_state == "VERIFYING" else ("red" if st.session_state.incident_state == "REOPENED" else "gray")),
            ("5. INFORM", "Public & Authority Feed", "gray")
        ]
        
        for title, desc, status in stages:
            if status == "green":
                st.markdown(f'<div class="stage-box" style="border-color: #059669; color: #34d399;"><b>{title}</b> — {desc} ✓</div>', unsafe_allow_html=True)
            elif status == "amber":
                st.markdown(f'<div class="stage-box stage-active"><b>{title}</b> — {desc}</div>', unsafe_allow_html=True)
            elif status == "cyan":
                st.markdown(f'<div class="stage-box stage-verifying"><b>{title}</b> — {desc}...</div>', unsafe_allow_html=True)
            elif status == "red":
                st.markdown(f'<div class="stage-box stage-reopened"><b>{title}</b> — {desc} 🚨</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="stage-box" style="color: #64748b;"><b>{title}</b> — {desc}</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("##### 🛡️ False Repair Catch Demo")
        st.info("Simulate an operator claiming 'Repaired' without closing Leak A valve. AQUAGUARD cross-verifies S1, S2, S3 sensors and auto-reopens!")
        
        if st.button("🔧 Simulate Operator Claiming 'Repaired'", use_container_width=True, type="primary"):
            st.session_state.incident_state = "VERIFYING"
            log_audit_event("Operator filed REPAIR COMPLETE claim → Initiated physical re-verification")
            st.rerun()

        if st.session_state.incident_state == "VERIFYING":
            time.sleep(1.5)
            st.session_state.incident_state = "REOPENED"
            log_audit_event("🚨 REPAIR VERIFICATION FAILED! Flow loss (38.4 L/min) persists. Ticket AUTO-REOPENED.")
            st.rerun()

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown("##### 🔗 Tamper-Evident SHA-256 Audit Log")
        st.caption("Append-only event ledger guarding against institutional cover-ups.")
        
        for item in st.session_state.audit_chain[:4]:
            st.markdown(f"""
            <div class="hash-log-item">
                <div style="color: #e2e8f0; font-weight: 600;">{item['event']}</div>
                <div style="display: flex; justify-content: space-between; color: #06b6d4; font-family: monospace; margin-top: 0.2rem;">
                    <span>Hash: {item['hash']}</span>
                    <span style="color: #64748b;">{item['time']}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
