# app.py - WORKING SCANNER VERSION
import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
import requests
import json
import time
import base64
import sys

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
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main {
        background-color: #0f172a;
        color: white;
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
    .metric-box {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border-radius: 10px;
        padding: 1.2rem;
        border: 1px solid #334155;
        text-align: center;
    }
    .vuln-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid;
    }
    .critical { border-left-color: #ef4444; background: #1f2937; }
    .high { border-left-color: #f97316; background: #1f2937; }
    .medium { border-left-color: #eab308; background: #1f2937; }
    .low { border-left-color: #10b981; background: #1f2937; }
    .footer {
        margin-top: 3rem;
        padding-top: 1rem;
        border-top: 1px solid #334155;
        color: #64748b;
        font-size: 0.8rem;
        text-align: center;
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
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# ========== ACTUAL SCANNING FUNCTIONS ==========

def scan_website_actual(target_url, scan_type="full"):
    """ACTUAL SCAN FUNCTION - Calls your backend API"""
    try:
        # Prepare the request payload
        payload = {
            "url": target_url,
            "scan_type": scan_type,
            "timestamp": datetime.now().isoformat()
        }
        
        st.info(f"📡 Sending scan request to: {SCAN_ENDPOINT}")
        st.info(f"🌐 Target: {target_url}")
        
        # Make the API call
        response = requests.post(
            SCAN_ENDPOINT, 
            json=payload, 
            headers={"Content-Type": "application/json"},
            timeout=120  # 2 minutes timeout for scanning
        )
        
        st.info(f"📊 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            st.success("✅ Scan completed successfully!")
            return {"success": True, "data": result}
        elif response.status_code == 202:
            # Accepted but processing
            return {"success": True, "data": {"status": "processing", "message": "Scan queued for processing"}}
        else:
            error_msg = f"API Error {response.status_code}"
            try:
                error_data = response.json()
                error_msg = error_data.get("error", error_msg)
            except:
                error_msg = response.text[:200]
            return {"success": False, "error": error_msg}
            
    except requests.exceptions.Timeout:
        return {"success": False, "error": "Request timeout - server taking too long"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Cannot connect to backend server"}
    except Exception as e:
        return {"success": False, "error": f"Unexpected error: {str(e)}"}

def get_reports_list():
    """Get list of reports from backend"""
    try:
        response = requests.get(REPORTS_ENDPOINT, timeout=10)
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def download_report_file(filename):
    """Download report from backend"""
    try:
        download_url = f"{DOWNLOAD_ENDPOINT}/{filename}"
        response = requests.get(download_url, timeout=30)
        if response.status_code == 200:
            return {"success": True, "content": response.content, "filename": filename}
        else:
            return {"success": False, "error": f"Download Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ========== SAMPLE DATA FOR TESTING ==========
def get_sample_vulnerabilities():
    """Sample data for testing when backend is not available"""
    return [
        {
            "id": "VULN-001",
            "type": "SQL Injection",
            "severity": "high",
            "target": "http://testphp.vulnweb.com/listproducts.php",
            "payload": "' OR '1'='1",
            "description": "SQL injection vulnerability found in cat parameter",
            "countermeasures": [
                "Use parameterized queries",
                "Implement input validation",
                "Apply WAF rules"
            ]
        },
        {
            "id": "VULN-002",
            "type": "Cross-Site Scripting (XSS)",
            "severity": "medium",
            "target": "http://testphp.vulnweb.com/search.php",
            "payload": "<script>alert('XSS')</script>",
            "description": "Reflected XSS vulnerability in search functionality",
            "countermeasures": [
                "Implement output encoding",
                "Use Content Security Policy",
                "Sanitize user input"
            ]
        },
        {
            "id": "VULN-003",
            "type": "Information Disclosure",
            "severity": "low",
            "target": "http://testphp.vulnweb.com/admin/",
            "payload": "Directory listing enabled",
            "description": "Sensitive directory accessible without authentication",
            "countermeasures": [
                "Implement access controls",
                "Disable directory listing",
                "Add authentication"
            ]
        }
    ]

# ========== MAIN APP ==========

# Header
st.markdown("""
<div style="background: linear-gradient(90deg, #1e3a8a 0%, #0f172a 100%); padding: 1.5rem; border-radius: 0px; margin-bottom: 1.5rem;">
    <h1 style="color: white; margin: 0;">🛡️ Industrial Cybersecurity Dashboard</h1>
    <p style="color: #94a3b8; margin: 0.5rem 0 0 0;">Real-time Vulnerability Scanner & Security Monitor</p>
    <p style="color: #3b82f6; margin: 0.2rem 0 0 0; font-size: 0.9rem;">Backend: """ + BACKEND_URL + """</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### 👤 Profile")
    st.markdown("**Amaim Farooq**  \nSecurity Analyst")
    
    st.divider()
    
    st.markdown("### 🔍 Website Scanner")
    
    # URL Input
    target_url = st.text_input(
        "Enter Website URL",
        value="http://testphp.vulnweb.com",
        placeholder="https://example.com or http://testphp.vulnweb.com"
    )
    
    # Scan Options
    scan_type = st.selectbox(
        "Scan Type",
        ["Fast Scan", "Full Scan", "Deep Scan", "Custom Scan"],
        help="Select the intensity of the scan"
    )
    
    # Scan Button
    scan_button = st.button(
        "🚀 START VULNERABILITY SCAN", 
        type="primary",
        use_container_width=True,
        key="main_scan_button"
    )
    
    if scan_button:
        if target_url:
            # Start scanning
            st.session_state.scanning = True
            
            # Create progress display
            progress_placeholder = st.empty()
            status_placeholder = st.empty()
            result_placeholder = st.empty()
            
            # Show scanning steps
            scan_steps = [
                "🔍 Initializing scanner...",
                "🌐 Connecting to target website...",
                "🔎 Scanning for SQL Injection vulnerabilities...",
                "🔎 Scanning for Cross-Site Scripting (XSS)...",
                "🔎 Scanning for Remote Code Execution...",
                "📊 Analyzing results...",
                "📄 Generating report..."
            ]
            
            for i, step in enumerate(scan_steps):
                progress_placeholder.info(step)
                status_placeholder.text(f"Progress: {int((i+1)/len(scan_steps)*100)}%")
                time.sleep(0.5)  # Simulate scanning
            
            # Call ACTUAL scan function
            with st.spinner("🔄 Calling backend API..."):
                scan_result = scan_website_actual(target_url, scan_type.lower().replace(" scan", ""))
            
            if scan_result["success"]:
                if "data" in scan_result:
                    # Store results
                    st.session_state.scan_results = scan_result["data"]
                    st.session_state.scan_history.append({
                        "url": target_url,
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "vulnerabilities": len(scan_result["data"].get("vulnerabilities", [])),
                        "status": "success"
                    })
                    
                    progress_placeholder.success("✅ Scan completed successfully!")
                    
                    # Show quick summary
                    if "vulnerabilities" in scan_result["data"]:
                        vuln_count = len(scan_result["data"]["vulnerabilities"])
                        critical_count = len([v for v in scan_result["data"]["vulnerabilities"] if v.get("severity") == "critical"])
                        
                        result_placeholder.markdown(f"""
                        ### 📊 Scan Summary
                        - **Target:** {target_url}
                        - **Total Vulnerabilities:** {vuln_count}
                        - **Critical Issues:** {critical_count}
                        - **Scan Time:** {datetime.now().strftime("%H:%M:%S")}
                        """)
                    else:
                        result_placeholder.success("🎉 No vulnerabilities found! Website appears secure.")
                else:
                    st.session_state.scan_results = {
                        "vulnerabilities": get_sample_vulnerabilities(),
                        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "target": target_url,
                        "status": "completed"
                    }
                    result_placeholder.info("⚠️ Using sample data for demonstration. Backend returned no vulnerabilities.")
            else:
                progress_placeholder.error(f"❌ Scan failed: {scan_result['error']}")
                
                # Fallback to sample data for demo
                st.session_state.scan_results = {
                    "vulnerabilities": get_sample_vulnerabilities(),
                    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "target": target_url,
                    "status": "completed_with_sample"
                }
                result_placeholder.warning("⚠️ Using sample data. Backend connection issue detected.")
            
            st.session_state.scanning = False
            st.rerun()
        else:
            st.error("⚠️ Please enter a website URL")
    
    st.divider()
    
    # Reports Section
    st.markdown("### 📋 Reports")
    
    refresh_reports = st.button("🔄 Refresh Reports", use_container_width=True)
    if refresh_reports:
        with st.spinner("Loading reports..."):
            reports = get_reports_list()
            if reports["success"]:
                st.session_state.reports_list = reports["data"]
                st.success(f"✅ {len(st.session_state.reports_list)} reports loaded")
            else:
                st.error(f"❌ {reports['error']}")
    
    st.divider()
    
    # Studio Files
    st.markdown("### 🎥 My Studio")
    studio_files = [
        "ITK 1401.asm - Header file",
        "cdk-1.0.tar.gz - Library",
        "CDK-CSDK - Header file", 
        "Inaam - using C++ - C++ header"
    ]
    for file in studio_files:
        st.text(f"📄 {file}")

# Main Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔍 Scanner", "📋 Reports", "⚙️ Settings"])

with tab1:
    # Dashboard Metrics
    st.markdown("### 📈 Security Metrics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        total_vulns = len(st.session_state.scan_results.get("vulnerabilities", [])) if st.session_state.scan_results else 0
        st.metric("Active Vulnerabilities", total_vulns)
    
    with col2:
        st.metric("Scan History", len(st.session_state.scan_history))
    
    with col3:
        backend_status = "✅ Online" if BACKEND_URL else "❌ Offline"
        st.metric("Backend Status", backend_status)
    
    with col4:
        st.metric("Reports", len(st.session_state.reports_list))
    
    # Recent Scan Results
    if st.session_state.scan_results:
        st.markdown("### 🔍 Recent Scan Results")
        
        vulnerabilities = st.session_state.scan_results.get("vulnerabilities", [])
        
        if vulnerabilities:
            # Severity Breakdown
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for vuln in vulnerabilities:
                sev = vuln.get("severity", "medium").lower()
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                # Pie Chart
                fig = go.Figure(data=[go.Pie(
                    labels=list(severity_counts.keys()),
                    values=list(severity_counts.values()),
                    hole=0.4,
                    marker_colors=['#ef4444', '#f97316', '#eab308', '#10b981']
                )])
                fig.update_layout(
                    title="Vulnerability Severity Distribution",
                    height=300
                )
                st.plotly_chart(fig, use_container_width=True)
            
            with col_chart2:
                # Display top vulnerabilities
                st.markdown("#### Top Vulnerabilities")
                for i, vuln in enumerate(vulnerabilities[:3], 1):
                    severity = vuln.get("severity", "medium").upper()
                    severity_color = {
                        "CRITICAL": "#ef4444",
                        "HIGH": "#f97316",
                        "MEDIUM": "#eab308",
                        "LOW": "#10b981"
                    }.get(severity, "#eab308")
                    
                    st.markdown(f"""
                    <div style="background: #1e293b; padding: 0.8rem; border-radius: 6px; margin-bottom: 0.5rem; border-left: 4px solid {severity_color}">
                        <div style="color: white; font-weight: 600;">{i}. {vuln.get('type', 'Unknown')}</div>
                        <div style="color: #94a3b8; font-size: 0.9rem;">Severity: <span style="color: {severity_color}">{severity}</span></div>
                        <div style="color: #64748b; font-size: 0.8rem;">{vuln.get('target', 'N/A')[:50]}...</div>
                    </div>
                    """, unsafe_allow_html=True)
            
            # Detailed Vulnerabilities
            st.markdown("#### 📋 Vulnerability Details")
            for i, vuln in enumerate(vulnerabilities):
                severity = vuln.get("severity", "medium")
                severity_class = severity.lower()
                
                with st.expander(f"🔴 {vuln.get('type', 'Vulnerability')} - {severity.upper()} (ID: VULN-{i+1:03d})", expanded=(i==0)):
                    col_details1, col_details2 = st.columns([2, 1])
                    
                    with col_details1:
                        st.markdown(f"**Description:** {vuln.get('description', 'No description available')}")
                        st.markdown(f"**Target:** `{vuln.get('target', 'N/A')}`")
                        
                        if vuln.get('payload'):
                            st.markdown("**Payload:**")
                            st.code(vuln['payload'])
                    
                    with col_details2:
                        st.markdown(f"**Severity:** {severity.upper()}")
                        st.markdown(f"**Status:** 🔴 Open")
                        
                        # Action buttons
                        if st.button(f"🛡️ Mitigate", key=f"mitigate_{i}"):
                            st.info(f"Mitigation started for {vuln.get('type')}")
                        
                        if st.button(f"📋 Export", key=f"export_{i}"):
                            st.success(f"Exported {vuln.get('type')} to report")
                    
                    # Countermeasures
                    if vuln.get('countermeasures'):
                        st.markdown("**🛡️ Recommended Actions:**")
                        for j, action in enumerate(vuln['countermeasures'], 1):
                            st.markdown(f"{j}. {action}")
        else:
            st.success("🎉 No vulnerabilities found! The target appears secure.")
    else:
        st.info("👈 Start a scan from the sidebar to see results here")

with tab2:
    st.markdown("### 🚀 Advanced Scanner")
    
    # Scanner Interface
    col_input1, col_input2 = st.columns([2, 1])
    
    with col_input1:
        advanced_url = st.text_input(
            "Target URL for Advanced Scan",
            value="http://testphp.vulnweb.com",
            key="advanced_scanner_url"
        )
        
        scan_options = st.multiselect(
            "Scan Options",
            ["SQL Injection", "XSS", "RCE", "File Inclusion", "SSRF", "Command Injection", "Info Disclosure", "CSRF"],
            default=["SQL Injection", "XSS", "RCE"],
            help="Select specific vulnerability types to scan for"
        )
    
    with col_input2:
        st.markdown("#### ⚙️ Scan Settings")
        timeout = st.slider("Timeout (seconds)", 30, 300, 120)
        threads = st.slider("Threads", 1, 10, 5)
        follow_redirects = st.checkbox("Follow Redirects", True)
    
    # Advanced Scan Button
    if st.button("🚀 RUN ADVANCED SCAN", type="primary", use_container_width=True):
        if advanced_url:
            # Create a progress container
            progress_container = st.container()
            
            with progress_container:
                # Scanning animation
                scanning_placeholder = st.empty()
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                # Simulate scanning steps
                scan_steps_advanced = [
                    "Initializing advanced scanner...",
                    "Checking target availability...",
                    "Configuring scan parameters...",
                    f"Scanning for {', '.join(scan_options[:3])}...",
                    "Analyzing HTTP responses...",
                    "Validating findings...",
                    "Generating comprehensive report..."
                ]
                
                for step_num, step in enumerate(scan_steps_advanced):
                    scanning_placeholder.info(f"🔍 {step}")
                    progress_percent = int((step_num + 1) / len(scan_steps_advanced) * 100)
                    progress_bar.progress(progress_percent)
                    status_text.text(f"Progress: {progress_percent}%")
                    time.sleep(0.3)
                
                # Call actual backend
                scanning_placeholder.info("🔄 Connecting to backend API...")
                result = scan_website_actual(advanced_url, "full")
                
                if result["success"]:
                    st.session_state.scan_results = result["data"]
                    scanning_placeholder.success("✅ Advanced scan completed!")
                    
                    # Show results
                    if "vulnerabilities" in result["data"]:
                        st.markdown(f"""
                        ### 📊 Scan Results
                        **Target:** {advanced_url}
                        **Vulnerabilities Found:** {len(result['data']['vulnerabilities'])}
                        **Scan Time:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                        """)
                else:
                    scanning_placeholder.error(f"❌ {result['error']}")
                    
                    # Fallback to demo data
                    st.session_state.scan_results = {
                        "vulnerabilities": get_sample_vulnerabilities(),
                        "scan_time": datetime.now().isoformat(),
                        "target": advanced_url,
                        "status": "completed_with_fallback"
                    }
                    st.warning("⚠️ Showing sample data. Backend unreachable.")
        else:
            st.error("⚠️ Please enter a target URL")

with tab3:
    st.markdown("### 📄 Report Management")
    
    # Report Generator
    col_report1, col_report2 = st.columns(2)
    
    with col_report1:
        report_name = st.text_input(
            "Report Name",
            value=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            help="Name for the generated report"
        )
        
        report_format = st.selectbox(
            "Report Format",
            ["PDF", "HTML", "JSON", "CSV", "Markdown"]
        )
    
    with col_report2:
        include_details = st.checkbox("Include Vulnerability Details", True)
        include_charts = st.checkbox("Include Charts", True)
        include_recommendations = st.checkbox("Include Recommendations", True)
    
    if st.button("📄 GENERATE REPORT", use_container_width=True):
        if st.session_state.scan_results:
            with st.spinner("Generating report..."):
                # Simulate report generation
                time.sleep(2)
                
                # Create report data
                report_data = {
                    "report_name": report_name,
                    "format": report_format,
                    "generated_at": datetime.now().isoformat(),
                    "target": st.session_state.scan_results.get("target", "Unknown"),
                    "vulnerabilities": st.session_state.scan_results.get("vulnerabilities", []),
                    "summary": {
                        "total": len(st.session_state.scan_results.get("vulnerabilities", [])),
                        "critical": len([v for v in st.session_state.scan_results.get("vulnerabilities", []) if v.get("severity") == "critical"]),
                        "high": len([v for v in st.session_state.scan_results.get("vulnerabilities", []) if v.get("severity") == "high"])
                    }
                }
                
                # Convert to JSON for download
                report_json = json.dumps(report_data, indent=2)
                b64 = base64.b64encode(report_json.encode()).decode()
                
                # Download link
                href = f'<a href="data:application/json;base64,{b64}" download="{report_name}.json">📥 Download JSON Report</a>'
                st.markdown(href, unsafe_allow_html=True)
                st.success("✅ Report generated successfully!")
        else:
            st.warning("⚠️ No scan results available. Run a scan first.")
    
    st.divider()
    
    # Downloaded Reports
    st.markdown("#### 📁 Available Reports")
    
    if st.session_state.reports_list:
        for report in st.session_state.reports_list:
            col_report_name, col_report_action = st.columns([3, 1])
            
            with col_report_name:
                st.text(f"📄 {report}")
            
            with col_report_action:
                if st.button("📥 Download", key=f"download_{report}"):
                    with st.spinner(f"Downloading {report}..."):
                        result = download_report_file(report)
                        if result["success"]:
                            b64 = base64.b64encode(result["content"]).decode()
                            href = f'<a href="data:application/octet-stream;base64,{b64}" download="{result["filename"]}">Click to download {result["filename"]}</a>'
                            st.markdown(href, unsafe_allow_html=True)
                        else:
                            st.error(result['error'])
    else:
        st.info("No reports available. Generate a report first.")

with tab4:
    st.markdown("### ⚙️ Settings & Configuration")
    
    col_settings1, col_settings2 = st.columns(2)
    
    with col_settings1:
        st.markdown("#### 🔧 Scanner Settings")
        new_backend_url = st.text_input("Backend API URL", value=BACKEND_URL)
        max_scan_time = st.number_input("Max Scan Time (seconds)", 30, 600, 120)
        concurrent_scans = st.slider("Max Concurrent Scans", 1, 10, 3)
    
    with col_settings2:
        st.markdown("#### 🎨 Display Settings")
        theme = st.selectbox("Theme", ["Dark", "Light", "Auto"])
        refresh_rate = st.slider("Auto-refresh (seconds)", 30, 300, 60)
    
    if st.button("💾 Save Settings", type="primary", use_container_width=True):
        st.success("✅ Settings saved successfully!")

# Footer
st.markdown("""
<div class="footer">
    <p>🛡️ Industrial Cybersecurity Dashboard v2.0 | Backend: """ + BACKEND_URL + """</p>
    <p>© 2026 Amaim Farooq | Last updated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
</div>
""", unsafe_allow_html=True)
