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
    .status-reported { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .status-assigned { background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }
    .status-in_progress { background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }
    .status-fixed { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .status-reopened { background-color: rgba(239, 68, 68, 0.3); color: #fecdd3; border: 1px solid #ef4444; }
    .status-closed { background-color: rgba(100, 116, 139, 0.2); color: #94a3b8; border: 1px solid #475569; }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# GLOBAL SHARED IN-MEMORY DATABASE (MULTI-USER SYNC ENGINE)
# ==============================================================================
@st.cache_resource
def get_global_database():
    """Returns a globally shared dictionary persisted across all users and page refreshes."""
    def _create_hash(event_text, previous_hash="0x00000000000000"):
        payload = f"{event_text}|{previous_hash}|{datetime.now().isoformat()}"
        return "0x" + hashlib.sha256(payload.encode()).hexdigest()[:14]

    initial_hash = _create_hash("AQUAGUARD Global Shared Database Initialized")
    
    return {
        "tickets": [
            {
                "id": "TCK-8042",
                "locality": "DMA Zone 4 — Sector 7 Main Rd",
                "severity": "Major Burst",
                "status": "Assigned",
                "crew": "Crew Alpha (Nordic Hydro)",
                "eta": "2 Hours",
                "reported_time": "10:14 AM",
                "details": "Heavy water burst near junction valve. Flowing onto road.",
                "pipe_spec": "350mm PVC Distribution Line",
                "dispute_count": 0
            }
        ],
        "audit_chain": [
            {
                "event": "AQUAGUARD Global Shared Database Initialized",
                "hash": initial_hash,
                "time": datetime.now().strftime("%I:%M:%S %p")
            }
        ],
        "incident_state": "ESCALATED"
    }

# Connect local session to global memory instance
db = get_global_database()

# ==============================================================================
# HELPER FUNCTIONS & SHA-256 AUDIT ENGINE
# ==============================================================================
def create_hash(event_text, previous_hash=""):
    payload = f"{event_text}|{previous_hash}|{datetime.now().isoformat()}"
    return "0x" + hashlib.sha256(payload.encode()).hexdigest()[:14]

def log_audit_event(event_text):
    prev_hash = db["audit_chain"][0]["hash"] if db["audit_chain"] else "0x00000000000000"
    new_hash = create_hash(event_text, prev_hash)
    db["audit_chain"].insert(0, {
        "event": event_text,
        "hash": new_hash,
        "time": datetime.now().strftime("%I:%M:%S %p")
    })

# ==============================================================================
# INITIALIZE LOCAL SESSION STATE
# ==============================================================================
if "app_role" not in st.session_state:
    st.session_state.app_role = "🏛️ Municipality Web Portal"

if "esp32_ip" not in st.session_state:
    st.session_state.esp32_ip = "192.168.1.50"

if "history_times" not in st.session_state:
    st.session_state.history_times = [datetime.now().strftime("%H:%M:%S") for _ in range(10)]
    st.session_state.history_s1 = [0.0] * 10
    st.session_state.history_s2 = [0.0] * 10
    st.session_state.history_s3 = [0.0] * 10

# ==============================================================================
# REAL-TIME HARDWARE TELEMETRY ENGINE (PURE LIVE ESP32 POLLING)
# ==============================================================================
def fetch_esp32_telemetry():
    """Polls the physical ESP32 HTTP endpoint for live sensor metrics."""
    try:
        url = f"http://{st.session_state.esp32_ip}/data"
        response = requests.get(url, timeout=0.8)
        if response.status_code == 200:
            data = response.json()
            s1 = round(float(data.get("s1", 0.0)), 1)
            s2 = round(float(data.get("s2", 0.0)), 1)
            s3 = round(float(data.get("s3", 0.0)), 1)
            return s1, s2, s3, True
    except Exception:
        pass
    
    # Strict fallback: Zeroed state if hardware endpoint is offline
    return 0.0, 0.0, 0.0, False

# ==============================================================================
# SIDEBAR CONTROL PANEL
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
st.sidebar.markdown("### 🌐 ESP32 Hardware Configuration")
st.session_state.esp32_ip = st.sidebar.text_input("ESP32 IP / Endpoint URL", value=st.session_state.esp32_ip)

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Sync Global Data"):
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
                <h1 style="margin: 0; font-size: 4.0rem; font-weight: 800; background: linear-gradient(to right, #22d3ee, #38bdf8, #3b82f6); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
                     NIRVAAN
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
        
        if not db["tickets"]:
            st.info("No active tickets reported in the system.")
        
        for tck in db["tickets"]:
            status_slug = tck['status'].lower().replace(" ", "_")
            status_class = f"status-{status_slug}"
            
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{tck['id']}</span>
                    <span class="ticket-badge {status_class}">{tck['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: 700; margin-top: 0.4rem; color: #f3f4f6;">📍 {tck['locality']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">{tck['details']}</div>
                <div style="font-size: 0.75rem; color: #64748b; margin-top: 0.5rem; font-family: monospace;">
                    Assigned: <b>{tck['crew']}</b> | Reported: {tck['reported_time']} | Severity: {tck['severity']} | Disputed Re-opens: {tck['dispute_count']}
                </div>
            </div>
            """, unsafe_allow_html=True)

            c_act1, c_act2, c_act3 = st.columns(3)
            with c_act1:
                if tck['status'] in ["Reported", "Reopened"]:
                    if st.button(f"🚀 Dispatch Crew Alpha", key=f"muni_dispatch_{tck['id']}"):
                        tck['status'] = "Assigned"
                        tck['crew'] = "Crew Alpha (Nordic Hydro)"
                        log_audit_event(f"Municipality dispatched Crew Alpha to Ticket {tck['id']}")
                        st.success("Repair Crew Dispatched!")
                        st.rerun()
            
            with c_act2:
                if tck['status'] in ["Fixed", "Repair Complete"]:
                    if st.button(f"🔍 Verify Physics & Close", key=f"muni_verify_{tck['id']}"):
                        s1, s2, s3, _ = fetch_esp32_telemetry()
                        loss = round(s1 - s2 - s3, 1)
                        if loss > 5.0:
                            tck['status'] = "Reopened"
                            tck['dispute_count'] += 1
                            db["incident_state"] = "REOPENED"
                            log_audit_event(f"🚨 Municipal Inspection FAILED for {tck['id']}! Sensor loss ({loss} L/min) persists. Ticket REOPENED.")
                            st.error("False Repair Detected by ESP32 sensors! Ticket auto-reopened.")
                        else:
                            tck['status'] = "Closed"
                            db["incident_state"] = "RESOLVED"
                            log_audit_event(f"✅ Municipal Admin verified repair for {tck['id']}. Ticket formally CLOSED.")
                            st.success("Repair verified by hardware. Case Closed!")
                        st.rerun()

            with c_act3:
                if tck['status'] == "Reopened":
                    st.warning("⚠️ High Priority Escalation Active!")

    with col2:
        st.markdown("##### 🔗 Real-Time Audit Log")
        for item in db["audit_chain"][:6]:
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
                db["tickets"].append({
                    "id": new_id,
                    "locality": loc,
                    "severity": sev,
                    "status": "Reported",
                    "crew": "Unassigned",
                    "eta": "Awaiting Triage",
                    "reported_time": datetime.now().strftime("%I:%M %p"),
                    "details": desc,
                    "pipe_spec": "Standard Distribution Pipe",
                    "dispute_count": 0
                })
                log_audit_event(f"Citizen submitted leak report {new_id} at {loc}")
                st.success(f"Report Submitted Successfully! Tracking ID: {new_id}")
                st.rerun()

    with c_right:
        st.markdown("##### 📱 Live Ticket Queue Across All Users")
        for tck in db["tickets"]:
            status_slug = tck['status'].lower().replace(" ", "_")
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{tck['id']}</span>
                    <span class="ticket-badge status-{status_slug}">{tck['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: bold; margin-top: 0.4rem;">{tck['locality']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">Assigned Crew: <b>{tck['crew']}</b></div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Est. Resolution Time: <b>{tck['eta']}</b></div>
            </div>
            """, unsafe_allow_html=True)

            if tck['status'] in ["Fixed", "Closed", "Repair Complete"]:
                col_disp1, col_disp2 = st.columns(2)
                with col_disp1:
                    if st.button("✅ Confirm Water Fixed", key=f"confirm_{tck['id']}"):
                        tck['status'] = "Closed"
                        log_audit_event(f"Citizen confirmed resolution for ticket {tck['id']}.")
                        st.success("Thank you for confirming!")
                        st.rerun()
                with col_disp2:
                    if st.button("🚨 Report False Repair", key=f"dispute_{tck['id']}"):
                        tck['status'] = "Reopened"
                        tck['dispute_count'] += 1
                        db["incident_state"] = "REOPENED"
                        log_audit_event(f"🚨 CITIZEN DISPUTE! Citizen reported FALSE REPAIR on {tck['id']}. Ticket re-escalated.")
                        st.error("Ticket re-opened and flagged for municipal audit!")
                        st.rerun()

# ==============================================================================
# INTERFACE 3: REPAIR CREW GROUND APP (CONNECTED TO GLOBAL QUEUE)
# ==============================================================================
elif st.session_state.app_role == "🛠️ Repair Crew Ground App":
    st.subheader("🛠️ Ground Repair Crew Mobile Portal")
    st.caption("Accept repair assignments, post status updates, log physical repairs, and estimate resolution times.")

    col_crew1, col_crew2 = st.columns([6, 6])

    # Filter assigned tasks directly from the global database
    assigned_tasks = [t for t in db["tickets"] if t['status'] not in ["Closed"]]

    with col_crew1:
        st.markdown("##### 👷 Active Task Assignments")
        if not assigned_tasks:
            st.info("No active repair tasks currently assigned.")
            
        for task in assigned_tasks:
            status_slug = task['status'].lower().replace(" ", "_")
            st.markdown(f"""
            <div class="role-card">
                <div style="display: flex; justify-content: space-between;">
                    <span style="font-weight: 800; color: #38bdf8; font-family: monospace;">{task['id']}</span>
                    <span class="ticket-badge status-{status_slug}">{task['status'].upper()}</span>
                </div>
                <div style="font-size: 0.9rem; font-weight: bold; margin-top: 0.4rem;">Location: {task['locality']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 0.2rem;">Pipeline Spec: {task['pipe_spec']}</div>
                <div style="font-size: 0.8rem; color: #94a3b8;">Details: {task['details']}</div>
            </div>
            """, unsafe_allow_html=True)

    with col_crew2:
        st.markdown("##### 📝 Submit Repair Status Update")
        if assigned_tasks:
            with st.form("crew_update_form"):
                t_id = st.selectbox("Select Assigned Ticket", [t['id'] for t in assigned_tasks])
                c_status = st.selectbox("Work Progress", ["In Progress", "Parts Replaced - Testing", "Repair Complete"])
                eta_update = st.text_input("Estimated Fix Completion", "45 Minutes")
                work_notes = st.text_area("Ground Repair Log", "Replaced worn gasket on Valve Leak A. Restored line pressure.")
                
                submit_work = st.form_submit_button("📤 Submit Repair Log")
                
                if submit_work:
                    for t in db["tickets"]:
                        if t['id'] == t_id:
                            t['status'] = c_status
                            t['eta'] = eta_update
                            t['details'] = work_notes
                    
                    log_audit_event(f"Crew logged work status '{c_status}' for ticket {t_id}")
                    st.success("Repair status logged and synced globally across all users!")
                    st.rerun()
        else:
            st.caption("Awaiting new dispatch assignments from Municipality Command.")

# ==============================================================================
# INTERFACE 4: IOT HARDWARE TELEMETRY DASHBOARD (ISOLATED NON-FLICKER FRAGMENT)
# ==============================================================================
else:
    @st.fragment(run_every=2)
    def render_iot_live_dashboard():
        node1_flow, node2_flow, node3_flow, is_hardware_live = fetch_esp32_telemetry()
        unaccounted_loss = round(node1_flow - node2_flow - node3_flow, 1)

        # Append to live history buffers
        st.session_state.history_times.append(datetime.now().strftime("%H:%M:%S"))
        st.session_state.history_s1.append(node1_flow)
        st.session_state.history_s2.append(node2_flow)
        st.session_state.history_s3.append(node3_flow)

        st.session_state.history_times = st.session_state.history_times[-10:]
        st.session_state.history_s1 = st.session_state.history_s1[-10:]
        st.session_state.history_s2 = st.session_state.history_s2[-10:]
        st.session_state.history_s3 = st.session_state.history_s3[-10:]

        if unaccounted_loss > 5.0:
            localized_node = "Valve Leak A (Right Branch — Node 03)"
        elif not is_hardware_live:
            localized_node = "Awaiting Live Hardware Signal..."
        else:
            localized_node = "System Nominal (No Active Leaks)"

        if db["incident_state"] == "REOPENED":
            banner_title = "🚨 CRITICAL INCIDENT #8042 — FALSE REPAIR CAUGHT!"
            banner_desc = f"Accountability Guard Triggered! Claimed repair rejected. Unaccounted loss of <span style='color: #ef4444; font-family: monospace; font-weight: bold;'>{unaccounted_loss} L/min</span> isolated at <b>{localized_node}</b>."
        elif db["incident_state"] == "RESOLVED":
            banner_title = "✅ INCIDENT #8042 — LEAK SUCCESSFULLY RESOLVED"
            banner_desc = "Physical flow balance restored across live S1, S2, and S3 sensors."
        else:
            banner_title = "⚠️ LIVE TELEMETRY FEED ACTIVE"
            banner_desc = f"Unaccounted Loss: <span style='color: #ef4444; font-family: monospace; font-weight: bold;'>{unaccounted_loss} L/min</span> | Localized Fault: <b>{localized_node}</b>"

        st.markdown(f"""
        <div class="banner-alarm">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
                <div>
                    <div style="font-size: 0.9rem; font-weight: 700; color: #fecdd3;">{banner_title}</div>
                    <div style="font-size: 0.8rem; color: #e2e8f0; margin-top: 0.2rem;">{banner_desc}</div>
                </div>
                <div style="text-align: right;">
                    <span style="font-family: monospace; font-size: 0.75rem; color: {'#34d399' if is_hardware_live else '#f87171'}; background: {'#064e3b' if is_hardware_live else '#450a0a'}; padding: 0.3rem 0.7rem; border-radius: 0.5rem; border: 1px solid {'#065f46' if is_hardware_live else '#7f1d1d'};">
                        ● {'LIVE ESP32 CONNECTED' if is_hardware_live else 'HARDWARE DISCONNECTED'}
                    </span>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_left, col_right = st.columns([7, 4])

        with col_left:
            st.markdown("##### 📡 Live Physical Sensor Telemetry")
            n_col1, n_col2, n_col3 = st.columns(3)
            
            with n_col1:
                st.markdown(f"""
                <div class="node-card">
                    <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #38bdf8; font-family: monospace;">
                        <span>ESP32 — S1 INPUT</span>
                        <span style="color: #34d399;">NODE-01</span>
                    </div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Main Supply</div>
                    <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #38bdf8; margin: 0.4rem 0;">
                        {node1_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
            with n_col2:
                st.markdown(f"""
                <div class="node-card">
                    <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #38bdf8; font-family: monospace;">
                        <span>ESP32 — S2 BRANCH A</span>
                        <span style="color: #38bdf8;">NODE-02</span>
                    </div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Branch Node A</div>
                    <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #22d3ee; margin: 0.4rem 0;">
                        {node2_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
            with n_col3:
                st.markdown(f"""
                <div class="node-card-danger">
                    <div style="display: flex; justify-content: space-between; font-size: 0.65rem; font-weight: 700; color: #f87171; font-family: monospace;">
                        <span>ESP32 — S3 BRANCH B</span>
                        <span style="color: #f87171;">NODE-03</span>
                    </div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: #f3f4f6; margin-top: 0.2rem;">Branch Node B</div>
                    <div style="font-size: 1.8rem; font-weight: 800; font-family: monospace; color: #ef4444; margin: 0.4rem 0;">
                        {node3_flow} <span style="font-size: 0.75rem; color: #94a3b8;">L/min</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            pipeline_html = f"""
            <div style="background-color: #0b1329; border: 1px solid #1e293b; border-radius: 1rem; padding: 1.25rem; margin-bottom: 1rem; text-align: center;">
                <div style="font-size: 0.85rem; font-weight: 700; color: #38bdf8; margin-bottom: 0.5rem;">
                    📐 Live Hardware Topology & Anomaly Localization
                </div>
                <div style="display: flex; justify-content: space-around; align-items: center; margin-top: 1rem;">
                    <div style="background: #0f172a; border: 1px solid #38bdf8; padding: 0.5rem 1rem; border-radius: 0.5rem; color: #38bdf8;">
                        <b>S1 Input</b><br>{node1_flow} L/min
                    </div>
                    <div style="color: #64748b; font-weight: bold;">➔</div>
                    <div style="background: #0f172a; border: 1px solid #22d3ee; padding: 0.5rem 1rem; border-radius: 0.5rem; color: #22d3ee;">
                        <b>S2 Branch A</b><br>{node2_flow} L/min
                    </div>
                    <div style="color: #64748b; font-weight: bold;">➔</div>
                    <div style="background: #450a0a; border: 1px solid #ef4444; padding: 0.5rem 1rem; border-radius: 0.5rem; color: #f87171;">
                        <b>S3 Branch B</b><br>{node3_flow} L/min
                    </div>
                </div>
                <div style="margin-top: 1rem; font-family: monospace; font-size: 0.8rem; color: #f87171;">
                    Isolated Anomaly: <b>{localized_node}</b> (Unaccounted Loss = {unaccounted_loss} L/min)
                </div>
            </div>
            """
            st.markdown(pipeline_html, unsafe_allow_html=True)

            fig = go.Figure()
            fig.add_trace(go.Scatter(x=st.session_state.history_times, y=st.session_state.history_s1, mode='lines+markers', name='S1 Input', line=dict(color='#38bdf8', width=2)))
            fig.add_trace(go.Scatter(x=st.session_state.history_times, y=st.session_state.history_s2, mode='lines+markers', name='S2 Branch A', line=dict(color='#22d3ee', width=2)))
            fig.add_trace(go.Scatter(x=st.session_state.history_times, y=st.session_state.history_s3, mode='lines+markers', name='S3 Branch B', line=dict(color='#ef4444', width=2)))
            
            fig.update_layout(
                template='plotly_dark',
                paper_bgcolor='#0b1329',
                plot_bgcolor='#030712',
                margin=dict(l=20, r=20, t=30, b=20),
                height=250,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_right:
            st.markdown("##### 🛡️ Physical Hardware Audit")
            
            if st.button("🔍 Check Physical Fix Status", use_container_width=True, type="primary"):
                if unaccounted_loss > 5.0:
                    db["incident_state"] = "REOPENED"
                    log_audit_event(f"🚨 REPAIR REJECTED! Live sensors measured {unaccounted_loss} L/min loss. Incident AUTO-REOPENED.")
                else:
                    db["incident_state"] = "RESOLVED"
                    log_audit_event("✅ Physical flow balanced. Incident RESOLVED.")
                st.rerun()

            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("##### 🔗 SHA-256 Audit Log")
            for item in db["audit_chain"][:4]:
                st.markdown(f"""
                <div class="hash-log-item">
                    <div style="color: #e2e8f0; font-weight: 600;">{item['event']}</div>
                    <div style="display: flex; justify-content: space-between; color: #06b6d4; font-family: monospace; margin-top: 0.2rem;">
                        <span>Hash: {item['hash']}</span>
                        <span style="color: #64748b;">{item['time']}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    render_iot_live_dashboard()
