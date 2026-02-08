# app.py
import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import requests
import json
import time
import io
import base64

# Backend API Configuration
BACKEND_URL = "https://webvul-service-122530594751.us-central1.run.app"
SCAN_ENDPOINT = f"{BACKEND_URL}/api/scan"
REPORTS_ENDPOINT = f"{BACKEND_URL}/api/reports"
DOWNLOAD_ENDPOINT = f"{BACKEND_URL}/reports"

# Page configuration
st.set_page_config(
    page_title="Industrial Cybersecurity Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://www.iec.ch/standards/62443',
        'Report a bug': None,
        'About': "# Industrial Security Dashboard v2.0\nIEC 62443-3-3 Compliance Monitor with Vulnerability Scanner"
    }
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #0f172a;
        color: #e2e8f0;
    }
    
    [data-testid="stSidebar"] {
        background-color: #1e293b;
    }
    
    .dashboard-header {
        background: linear-gradient(90deg, #1e3a8a 0%, #0f172a 100%);
        padding: 1.5rem;
        border-radius: 0px;
        margin-bottom: 1.5rem;
        border-bottom: 2px solid #3b82f6;
    }
    
    .vuln-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 1.2rem;
        margin-bottom: 1rem;
        border: 1px solid #334155;
        transition: all 0.3s ease;
    }
    
    .vuln-card:hover {
        border-color: #3b82f6;
        box-shadow: 0 4px 12px rgba(59, 130, 246, 0.2);
    }
    
    .critical {
        border-left: 4px solid #ef4444;
    }
    
    .high {
        border-left: 4px solid #f97316;
    }
    
    .medium {
        border-left: 4px solid #eab308;
    }
    
    .low {
        border-left: 4px solid #10b981;
    }
    
    .severity-badge {
        padding: 0.3rem 0.8rem;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .badge-critical {
        background-color: #7f1d1d;
        color: #fecaca;
    }
    
    .badge-high {
        background-color: #7c2d12;
        color: #fed7aa;
    }
    
    .badge-medium {
        background-color: #713f12;
        color: #fef08a;
    }
    
    .badge-low {
        background-color: #064e3b;
        color: #a7f3d0;
    }
    
    .metric-box {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-radius: 10px;
        padding: 1.2rem;
        border: 1px solid #334155;
        text-align: center;
    }
    
    .scan-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-radius: 10px;
        padding: 1.5rem;
        border: 2px solid #3b82f6;
        margin-bottom: 1.5rem;
    }
    
    .report-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border: 1px solid #334155;
    }
    
    .dataframe {
        background-color: #1e293b !important;
        color: #e2e8f0 !important;
    }
    
    .dataframe th {
        background-color: #0f172a !important;
        color: #94a3b8 !important;
        font-weight: 600 !important;
    }
    
    .stButton > button {
        background-color: #3b82f6;
        color: white;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }
    
    .stButton > button:hover {
        background-color: #2563eb;
    }
    
    .footer {
        margin-top: 3rem;
        padding-top: 1rem;
        border-top: 1px solid #334155;
        color: #64748b;
        font-size: 0.8rem;
        text-align: center;
    }
    
    .code-block {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 0.8rem;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 0.9rem;
        color: #10b981;
        margin: 0.5rem 0;
        overflow-x: auto;
    }
    
    .status-success {
        color: #10b981;
        font-weight: 600;
    }
    
    .status-error {
        color: #ef4444;
        font-weight: 600;
    }
    
    .status-warning {
        color: #f59e0b;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'reports_list' not in st.session_state:
    st.session_state.reports_list = []
if 'scanning' not in st.session_state:
    st.session_state.scanning = False

# API Functions
def scan_website(target_url, scan_type="full"):
    """Scan website using backend API"""
    try:
        payload = {
            "url": target_url,
            "scan_type": scan_type
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        response = requests.post(SCAN_ENDPOINT, json=payload, headers=headers, timeout=30)
        
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"API Error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Connection Error: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected Error: {str(e)}"}

def get_reports():
    """Get list of reports from backend"""
    try:
        response = requests.get(REPORTS_ENDPOINT, timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"API Error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Connection Error: {str(e)}"}

def download_report(filename):
    """Download report from backend"""
    try:
        download_url = f"{DOWNLOAD_ENDPOINT}/{filename}"
        response = requests.get(download_url, timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "content": response.content, "filename": filename}
        else:
            return {"success": False, "error": f"Download Error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"success": False, "error": f"Connection Error: {str(e)}"}

def process_scan_results(results):
    """Process and format scan results for display"""
    if not results or "vulnerabilities" not in results:
        return []
    
    vulnerabilities = []
    
    for i, vuln in enumerate(results.get("vulnerabilities", [])):
        severity_map = {
            "critical": "CRITICAL",
            "high": "HIGH", 
            "medium": "MEDIUM",
            "low": "LOW"
        }
        
        severity = vuln.get("severity", "medium").lower()
        display_severity = severity_map.get(severity, "MEDIUM")
        
        vulnerability = {
            "id": f"VULN-{i+1:03d}",
            "finding": vuln.get("type", "Unknown Vulnerability"),
            "severity": display_severity,
            "severity_class": severity,
            "badge_class": f"badge-{severity}",
            "requirement": vuln.get("requirement", "FR 3 - System Integrity"),
            "target": vuln.get("target", "Unknown"),
            "payload": vuln.get("payload", "No payload available"),
            "description": vuln.get("description", "No description available"),
            "countermeasures": vuln.get("countermeasures", [
                "Implement input validation",
                "Apply security patches",
                "Review and refactor code"
            ]),
            "status": "OPEN",
            "discovered": datetime.now().strftime("%Y-%m-%d"),
            "affected_assets": vuln.get("affected_count", 1)
        }
        vulnerabilities.append(vulnerability)
    
    return vulnerabilities

# Main Header
st.markdown("""
<div class="dashboard-header">
    <h1 style="color: white; margin: 0; font-size: 2rem;">🛡️ Industrial Cybersecurity Dashboard</h1>
    <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">Vulnerability Scanner & IEC 62443-3-3 Compliance Monitor</p>
    <p style="color: #3b82f6; margin: 0.2rem 0 0 0; font-size: 0.9rem;">Backend Connected: """ + BACKEND_URL + """</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    # Profile Section
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #3b82f6, #8b5cf6); border-radius: 50%; margin: 0 auto 1rem auto; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; color: white;">
            AF
        </div>
        <h3 style="color: white; margin: 0;">Amaim Farooq</h3>
        <p style="color: #94a3b8; margin: 0.2rem 0 1rem 0;">Security Analyst</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Quick Scan Section
    st.markdown("### 🔍 Quick Scan")
    
    target_url = st.text_input(
        "Target URL",
        value="http://testphp.vulnweb.com",
        placeholder="Enter website URL to scan"
    )
    
    scan_type = st.selectbox(
        "Scan Type",
        ["full", "fast", "deep"],
        help="Full: Comprehensive scan, Fast: Quick scan, Deep: In-depth analysis"
    )
    
    if st.button("🚀 Start Scan", use_container_width=True):
        if target_url:
            st.session_state.scanning = True
            with st.spinner("Scanning website..."):
                result = scan_website(target_url, scan_type)
                
                if result["success"]:
                    st.session_state.scan_results = result["data"]
                    st.success("✅ Scan completed successfully!")
                    
                    # Refresh reports list
                    reports_result = get_reports()
                    if reports_result["success"]:
                        st.session_state.reports_list = reports_result["data"]
                else:
                    st.error(f"❌ Scan failed: {result['error']}")
                
                st.session_state.scanning = False
                st.rerun()
        else:
            st.warning("⚠️ Please enter a target URL")
    
    st.markdown("---")
    
    # Reports Section
    st.markdown("### 📋 Reports")
    
    if st.button("🔄 Refresh Reports", use_container_width=True):
        with st.spinner("Loading reports..."):
            reports_result = get_reports()
            if reports_result["success"]:
                st.session_state.reports_list = reports_result["data"]
                st.success(f"✅ Loaded {len(st.session_state.reports_list)} reports")
            else:
                st.error(f"❌ Failed to load reports: {reports_result['error']}")
    
    st.markdown("---")
    
    # System Status
    st.markdown("### 📊 System Status")
    
    # Test backend connection
    if st.button("🔗 Test Connection", use_container_width=True):
        try:
            response = requests.get(f"{BACKEND_URL}/health", timeout=5)
            if response.status_code == 200:
                st.success("✅ Backend connected")
            else:
                st.warning(f"⚠️ Backend status: {response.status_code}")
        except:
            st.error("❌ Backend unreachable")
    
    st.markdown("---")
    
    # Studio Files
    st.markdown("### 🎥 My Studio")
    
    studio_files = [
        {"Name": "ITK 1401.asm", "Size": "2.5 KB", "Status": "✅"},
        {"Name": "cdk-1.0.tar.gz", "Size": "15.2 MB", "Status": "✅"},
        {"Name": "CDK-CSDK", "Size": "8.7 MB", "Status": "⏳"},
        {"Name": "Inaam - using C++", "Size": "3.1 MB", "Status": "✅"}
    ]
    
    for file in studio_files:
        st.markdown(f"""
        <div style="background: #1e293b; padding: 0.6rem; border-radius: 6px; margin-bottom: 0.3rem;">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <span style="color: white; font-size: 0.9rem;">{file['Name']}</span>
                <span style="color: #94a3b8; font-size: 0.8rem;">{file['Size']}</span>
            </div>
            <div style="color: #64748b; font-size: 0.75rem;">Status: {file['Status']}</div>
        </div>
        """, unsafe_allow_html=True)

# Main content with tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["🏠 Dashboard", "🔍 Scanner", "📋 Reports", "📊 Analytics", "⚙️ Settings"])

with tab1:
    # Overview metrics
    st.markdown("### System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_vulns = len(st.session_state.scan_results.get("vulnerabilities", [])) if st.session_state.scan_results else 0
        st.markdown(f"""
        <div class="metric-box">
            <div style="font-size: 0.9rem; color: #94a3b8;">Active Vulnerabilities</div>
            <div style="font-size: 2rem; font-weight: 700; color: white;">{total_vulns}</div>
            <div style="font-size: 0.8rem; color: {'#10b981' if total_vulns == 0 else '#ef4444'};">
                {'✅ All Clear' if total_vulns == 0 else '⚠️ Needs Attention'}
            </div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        <div class="metric-box">
            <div style="font-size: 0.9rem; color: #94a3b8;">Reports Generated</div>
            <div style="font-size: 2rem; font-weight: 700; color: white;">{len(st.session_state.reports_list)}</div>
            <div style="font-size: 0.8rem; color: #3b82f6;">↑ Today: {len([r for r in st.session_state.reports_list if 'today' in r.lower()])}</div>
        </div>
        """.format(len=len(st.session_state.reports_list)), unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
        <div class="metric-box">
            <div style="font-size: 0.9rem; color: #94a3b8;">Compliance Score</div>
            <div style="font-size: 2rem; font-weight: 700; color: white;">{score}%</div>
            <div style="font-size: 0.8rem; color: {'#10b981' if score >= 80 else '#eab308' if score >= 60 else '#ef4444'};">
                {status}
            </div>
        </div>
        """.format(
            score=85 if total_vulns == 0 else 65,
            status="✅ Compliant" if total_vulns == 0 else "⚠️ Needs Improvement"
        ), unsafe_allow_html=True)
    
    with col4:
        st.markdown("""
        <div class="metric-box">
            <div style="font-size: 0.9rem; color: #94a3b8;">Last Scan</div>
            <div style="font-size: 1.5rem; font-weight: 700; color: white;">{time}</div>
            <div style="font-size: 0.8rem; color: #94a3b8;">{status}</div>
        </div>
        """.format(
            time=st.session_state.scan_results.get("scan_time", "Never") if st.session_state.scan_results else "Never",
            status="✅ Success" if st.session_state.scan_results else "⏳ Pending"
        ), unsafe_allow_html=True)
    
    # Recent Activity
    st.markdown("### 📈 Recent Activity")
    
    if st.session_state.scanning:
        st.info("🔄 Scan in progress...")
        progress_bar = st.progress(0)
        for percent_complete in range(100):
            time.sleep(0.02)
            progress_bar.progress(percent_complete + 1)
    
    elif st.session_state.scan_results:
        vulnerabilities = process_scan_results(st.session_state.scan_results)
        
        if vulnerabilities:
            # Severity Chart
            severity_counts = {}
            for vuln in vulnerabilities:
                sev = vuln["severity"]
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            col1, col2 = st.columns(2)
            
            with col1:
                fig = go.Figure(data=[go.Pie(
                    labels=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    hole=0.4,
                    marker_colors=['#ef4444', '#f97316', '#eab308', '#10b981']
                )])
                fig.update_layout(
                    title="Vulnerability Severity Distribution",
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#e2e8f0',
                    height=300
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Top vulnerabilities
                st.markdown("#### Top Vulnerabilities")
                for vuln in vulnerabilities[:3]:
                    st.markdown(f"""
                    <div style="background: #1e293b; padding: 0.8rem; border-radius: 6px; margin-bottom: 0.5rem; border-left: 4px solid {'#ef4444' if vuln['severity'] == 'CRITICAL' else '#f97316' if vuln['severity'] == 'HIGH' else '#eab308'}">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: white; font-weight: 500;">{vuln['finding']}</span>
                            <span style="color: {'#ef4444' if vuln['severity'] == 'CRITICAL' else '#f97316' if vuln['severity'] == 'HIGH' else '#eab308'}; font-size: 0.8rem;">
                                {vuln['severity']}
                            </span>
                        </div>
                        <div style="color: #94a3b8; font-size: 0.8rem; margin-top: 0.3rem;">{vuln['target'][:50]}...</div>
                    </div>
                    """, unsafe_allow_html=True)
        else:
            st.success("🎉 No vulnerabilities found!")
    else:
        st.info("👈 Start a scan from the sidebar to see results here")

with tab2:
    st.markdown("### 🚀 Website Vulnerability Scanner")
    
    # Scanner Card
    st.markdown('<div class="scan-card">', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### Target Configuration")
        scan_url = st.text_input(
            "Website URL",
            value=target_url if 'target_url' in locals() else "http://testphp.vulnweb.com",
            key="scanner_url"
        )
        
        scan_mode = st.selectbox(
            "Scan Mode",
            ["Fast Scan", "Full Scan", "Deep Scan", "Custom Scan"],
            help="Select scan intensity"
        )
        
        custom_options = st.multiselect(
            "Scan Options",
            ["SQL Injection", "XSS", "RCE", "File Inclusion", "SSRF", "Command Injection", "Info Disclosure"],
            default=["SQL Injection", "XSS", "RCE"]
        )
    
    with col2:
        st.markdown("#### Scan Statistics")
        st.metric("Average Scan Time", "45s")
        st.metric("Last Scan Duration", "38s" if st.session_state.scan_results else "N/A")
        st.metric("Vulnerabilities Found", len(st.session_state.scan_results.get("vulnerabilities", [])) if st.session_state.scan_results else 0)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Advanced Options
    with st.expander("⚙️ Advanced Options"):
        col1, col2, col3 = st.columns(3)
        
        with col1:
            thread_count = st.slider("Threads", 1, 10, 5)
            timeout = st.number_input("Timeout (seconds)", 10, 300, 30)
        
        with col2:
            follow_redirects = st.checkbox("Follow Redirects", True)
            verify_ssl = st.checkbox("Verify SSL", False)
        
        with col3:
            user_agent = st.selectbox(
                "User Agent",
                ["Default", "Chrome", "Firefox", "Mobile", "Custom"]
            )
            proxy = st.text_input("Proxy (optional)")
    
    # Scan Button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.button("🚀 START VULNERABILITY SCAN", use_container_width=True, type="primary"):
            if scan_url:
                st.session_state.scanning = True
                
                # Show scan progress
                scan_placeholder = st.empty()
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                scan_steps = [
                    "Initializing scanner...",
                    "Checking target availability...",
                    "Scanning for SQL Injection...",
                    "Scanning for XSS vulnerabilities...",
                    "Scanning for RCE vulnerabilities...",
                    "Analyzing results...",
                    "Generating report..."
                ]
                
                for i, step in enumerate(scan_steps):
                    scan_placeholder.info(f"🔍 {step}")
                    status_text.text(f"Progress: {int((i+1)/len(scan_steps)*100)}%")
                    progress_bar.progress((i+1)/len(scan_steps))
                    time.sleep(0.5)
                
                # Call backend API
                result = scan_website(scan_url, "full")
                
                if result["success"]:
                    st.session_state.scan_results = result["data"]
                    scan_placeholder.success("✅ Scan completed successfully!")
                    
                    # Show summary
                    if "vulnerabilities" in result["data"]:
                        vuln_count = len(result["data"]["vulnerabilities"])
                        critical_count = len([v for v in result["data"]["vulnerabilities"] if v.get("severity") == "critical"])
                        
                        st.markdown(f"""
                        ### 📊 Scan Summary
                        - **Target:** {scan_url}
                        - **Vulnerabilities Found:** {vuln_count}
                        - **Critical:** {critical_count}
                        - **Scan Duration:** {result['data'].get('scan_duration', 'N/A')}
                        - **Timestamp:** {result['data'].get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
                        """)
                else:
                    scan_placeholder.error(f"❌ Scan failed: {result['error']}")
                
                st.session_state.scanning = False
                st.rerun()
            else:
                st.warning("⚠️ Please enter a target URL")
    
    # Recent Scan Results
    if st.session_state.scan_results:
        st.markdown("### 📋 Scan Results")
        
        vulnerabilities = process_scan_results(st.session_state.scan_results)
        
        for vuln in vulnerabilities:
            with st.container():
                st.markdown(f'<div class="vuln-card {vuln["severity_class"]}">', unsafe_allow_html=True)
                
                with st.expander(f"**{vuln['finding']}** - {vuln['id']}", expanded=False):
                    col1, col2 = st.columns([2, 1])
                    
                    with col1:
                        st.markdown(f"**Severity:** <span class='severity-badge {vuln['badge_class']}'>{vuln['severity']}</span>", unsafe_allow_html=True)
                        st.markdown(f"**Target:** `{vuln['target']}`")
                        st.markdown(f"**Description:** {vuln['description']}")
                    
                    with col2:
                        st.markdown(f"**Status:** {vuln['status']}")
                        st.markdown(f"**Discovered:** {vuln['discovered']}")
                        st.markdown(f"**Affected Assets:** {vuln['affected_assets']}")
                    
                    # Payload
                    st.markdown("**Payload:**")
                    st.code(vuln['payload'], language='text')
                    
                    # Countermeasures
                    st.markdown("**Recommended Actions:**")
                    for i, cm in enumerate(vuln['countermeasures'], 1):
                        st.markdown(f"{i}. {cm}")
                
                st.markdown('</div>', unsafe_allow_html=True)

with tab3:
    st.markdown("### 📋 Vulnerability Reports")
    
    # Refresh reports button
    if st.button("🔄 Refresh Reports List", key="refresh_reports"):
        with st.spinner("Loading reports..."):
            reports_result = get_reports()
            if reports_result["success"]:
                st.session_state.reports_list = reports_result["data"]
                st.success(f"✅ Loaded {len(st.session_state.reports_list)} reports")
            else:
                st.error(f"❌ Failed to load reports: {reports_result['error']}")
    
    # Reports list
    if st.session_state.reports_list:
        st.markdown(f"#### Available Reports ({len(st.session_state.reports_list)})")
        
        for report in st.session_state.reports_list:
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.markdown(f"""
                <div class="report-card">
                    <div style="font-weight: 600; color: white;">{report}</div>
                    <div style="color: #94a3b8; font-size: 0.9rem;">Size: Unknown | Created: Recent</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                if st.button(f"📥 Download", key=f"dl_{report}"):
                    with st.spinner(f"Downloading {report}..."):
                        result = download_report(report)
                        if result["success"]:
                            # Create download button
                            b64 = base64.b64encode(result["content"]).decode()
                            href = f'<a href="data:application/octet-stream;base64,{b64}" download="{result["filename"]}">Click to download {result["filename"]}</a>'
                            st.markdown(href, unsafe_allow_html=True)
                            st.success("✅ Download ready!")
                        else:
                            st.error(f"❌ Download failed: {result['error']}")
            
            with col3:
                if st.button(f"👁️ View", key=f"view_{report}"):
                    st.info(f"Viewing report: {report}")
                    # Here you would parse and display the report content
                    # For now, show a placeholder
                    st.json({"report_name": report, "status": "available", "action": "Implement proper parsing for actual report format"})
    
    else:
        st.info("No reports available. Run a scan first!")
    
    # Report Generator
    st.markdown("---")
    st.markdown("### 📄 Generate New Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        report_name = st.text_input("Report Name", value=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        report_format = st.selectbox("Format", ["PDF", "HTML", "JSON", "CSV"])
    
    with col2:
        include_charts = st.checkbox("Include Charts", True)
        include_details = st.checkbox("Include Vulnerability Details", True)
        include_recommendations = st.checkbox("Include Recommendations", True)
    
    if st.button("📄 Generate Report", use_container_width=True):
        if st.session_state.scan_results:
            # Simulate report generation
            with st.spinner("Generating report..."):
                time.sleep(2)
                
                # Create sample report data
                report_data = {
                    "report_name": report_name,
                    "format": report_format,
                    "generated_at": datetime.now().isoformat(),
                    "scan_results": st.session_state.scan_results,
                    "summary": {
                        "total_vulnerabilities": len(st.session_state.scan_results.get("vulnerabilities", [])),
                        "critical_count": len([v for v in st.session_state.scan_results.get("vulnerabilities", []) if v.get("severity") == "critical"]),
                        "scan_duration": st.session_state.scan_results.get("scan_duration", "N/A")
                    }
                }
                
                # Show preview
                st.success("✅ Report generated successfully!")
                st.json(report_data)
                
                # Download button
                report_json = json.dumps(report_data, indent=2)
                b64 = base64.b64encode(report_json.encode()).decode()
                href = f'<a href="data:application/json;base64,{b64}" download="{report_name}.json">📥 Download JSON Report</a>'
                st.markdown(href, unsafe_allow_html=True)
        else:
            st.warning("⚠️ No scan results available. Please run a scan first.")

with tab4:
    st.markdown("### 📊 Analytics & Insights")
    
    # Compliance analytics
    st.markdown("#### IEC 62443-3-3 Compliance Analytics")
    
    compliance_data = pd.DataFrame({
        "Requirement": ["FR 3 - System Integrity", "FR 4 - Data Confidentiality", 
                       "SD.04.01 - Secure Development", "SD.06.01 - Logging & Monitoring",
                       "FR 5 - Use Control", "FR 6 - Data Integrity"],
        "Compliance": [35, 70, 40, 85, 90, 60],
        "Vulnerabilities": [2, 1, 3, 0, 0, 1],
        "Last Audit": ["2026-02-07", "2026-02-07", "2026-01-15", "2026-01-10", "2025-12-20", "2026-01-30"]
    })
    
    # Compliance chart
    fig = px.bar(compliance_data, x='Requirement', y='Compliance',
                 color='Compliance', color_continuous_scale='RdYlGn',
                 title="Compliance Level by Requirement")
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#e2e8f0',
        height=400
    )
    st.plotly_chart(fig, use_container_width=True)
    
    # Trend analysis
    st.markdown("#### 📈 Vulnerability Trend Analysis")
    
    trend_data = pd.DataFrame({
        'Month': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
        'Critical': [3, 2, 4, 3, 2, 1, 2, 3, 1, 2, 1, 0],
        'High': [5, 4, 6, 5, 4, 3, 4, 5, 3, 4, 2, 1],
        'Medium': [8, 7, 9, 8, 7, 6, 7, 8, 6, 7, 5, 4],
        'Low': [12, 10, 14, 12, 11, 9, 10, 12, 8, 10, 7, 5]
    })
    
    fig2 = go.Figure()
    fig2.add_trace(go.Scatter(x=trend_data['Month'], y=trend_data['Critical'], 
                             name='Critical', line=dict(color='#ef4444', width=3)))
    fig2.add_trace(go.Scatter(x=trend_data['Month'], y=trend_data['High'], 
                             name='High', line=dict(color='#f97316', width=3)))
    fig2.add_trace(go.Scatter(x=trend_data['Month'], y=trend_data['Medium'], 
                             name='Medium', line=dict(color='#eab308', width=3)))
    fig2.add_trace(go.Scatter(x=trend_data['Month'], y=trend_data['Low'], 
                             name='Low', line=dict(color='#10b981', width=3)))
    
    fig2.update_layout(
        title="Monthly Vulnerability Trends",
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font_color='#e2e8f0',
        height=400
    )
    
    st.plotly_chart(fig2, use_container_width=True)

with tab5:
    st.markdown("### ⚙️ Settings & Configuration")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🎨 Display Settings")
        
        theme = st.selectbox(
            "Theme",
            ["Dark (Default)", "Light", "Auto"],
            index=0
        )
        
        refresh_rate = st.slider(
            "Auto-refresh (seconds)",
            min_value=30,
            max_value=300,
            value=60,
            step=30
        )
        
        st.markdown("#### 🔔 Notifications")
        email_alerts = st.checkbox("Email Alerts", value=True)
        critical_only = st.checkbox("Critical Only", value=False)
        daily_summary = st.checkbox("Daily Summary", value=True)
    
    with col2:
        st.markdown("#### 🔧 Scanner Settings")
        
        # Backend URL configuration
        backend_url = st.text_input(
            "Backend API URL",
            value=BACKEND_URL,
            help="Change backend API endpoint if needed"
        )
        
        max_scan_time = st.number_input(
            "Maximum Scan Time (seconds)",
            min_value=30,
            max_value=600,
            value=120,
            step=30
        )
        
        concurrent_scans = st.slider(
            "Maximum Concurrent Scans",
            min_value=1,
            max_value=10,
            value=3
        )
        
        st.markdown("#### 💾 Data Settings")
        data_retention = st.selectbox(
            "Data Retention",
            ["30 days", "90 days", "180 days", "1 year", "Forever"],
            index=1
        )
    
    # API Key Management
    st.markdown("---")
    st.markdown("#### 🔐 API Authentication")
    
    api_key = st.text_input("API Key", type="password", value="••••••••••••••••")
    
    col_test, col_save = st.columns(2)
    with col_test:
        if st.button("Test API Connection", use_container_width=True):
            try:
                response = requests.get(f"{backend_url}/health", timeout=5)
                if response.status_code == 200:
                    st.success("✅ API Connection Successful")
                else:
                    st.warning(f"⚠️ API Response: {response.status_code}")
            except Exception as e:
                st.error(f"❌ Connection Failed: {str(e)}")
    
    with col_save:
        if st.button("Save Settings", type="primary", use_container_width=True):
            st.success("✅ Settings saved successfully!")
            time.sleep(1)
            st.rerun()

# Footer
st.markdown("""
<div class="footer">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap;">
        <div>🛡️ Industrial Cybersecurity Dashboard v2.1</div>
        <div>Backend: """ + BACKEND_URL + """</div>
        <div>Last Updated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</div>
    </div>
    <div style="margin-top: 0.5rem; color: #475569; font-size: 0.75rem;">
        © 2026 Amaim Farooq | IEC 62443-3-3 Compliance | Vulnerability Scanning Engine
    </div>
</div>
""", unsafe_allow_html=True)

# Requirements.txt content display
with st.sidebar:
    with st.expander("📦 Dependencies"):
        st.code("""streamlit==1.28.0
pandas==2.1.3
plotly==5.17.0
numpy==1.24.3
requests==2.31.0""", language="txt")
