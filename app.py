
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

# Add compatibility imports
try:
    import numpy as np
except ImportError:
    st.error("numpy not installed. Please check requirements.txt")

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

# Simple CSS - No complex styling that might break
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
    .metric-box {
        background: #1e293b;
        border-radius: 10px;
        padding: 1rem;
        border: 1px solid #334155;
        text-align: center;
    }
    .vuln-card {
        background: #1e293b;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid;
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

# API Functions with error handling
def scan_website(target_url, scan_type="full"):
    """Scan website using backend API"""
    try:
        payload = {"url": target_url, "scan_type": scan_type}
        response = requests.post(SCAN_ENDPOINT, json=payload, timeout=30)
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def get_reports():
    """Get list of reports from backend"""
    try:
        response = requests.get(REPORTS_ENDPOINT, timeout=10)
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": f"API Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

def download_report(filename):
    """Download report from backend"""
    try:
        download_url = f"{DOWNLOAD_ENDPOINT}/{filename}"
        response = requests.get(download_url, timeout=10)
        if response.status_code == 200:
            return {"success": True, "content": response.content, "filename": filename}
        else:
            return {"success": False, "error": f"Download Error: {response.status_code}"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Main Header
st.title("🛡️ Industrial Cybersecurity Dashboard")
st.caption(f"Backend: {BACKEND_URL}")

# Sidebar
with st.sidebar:
    st.header("🔍 Quick Scan")
    target_url = st.text_input("Target URL", value="http://testphp.vulnweb.com")
    
    if st.button("🚀 Start Scan", use_container_width=True):
        if target_url:
            st.session_state.scanning = True
            with st.spinner("Scanning website..."):
                result = scan_website(target_url)
                if result["success"]:
                    st.session_state.scan_results = result["data"]
                    st.success("✅ Scan completed!")
                else:
                    st.error(f"❌ Scan failed: {result['error']}")
                st.session_state.scanning = False
    
    st.divider()
    
    st.header("📋 Reports")
    if st.button("🔄 Refresh Reports", use_container_width=True):
        with st.spinner("Loading reports..."):
            reports_result = get_reports()
            if reports_result["success"]:
                st.session_state.reports_list = reports_result["data"]
                st.success(f"✅ Loaded {len(st.session_state.reports_list)} reports")
    
    st.divider()
    
    st.header("🎥 My Studio")
    studio_files = [
        {"Name": "ITK 1401.asm", "Size": "2.5 KB"},
        {"Name": "cdk-1.0.tar.gz", "Size": "15.2 MB"},
        {"Name": "CDK-CSDK", "Size": "8.7 MB"},
        {"Name": "Inaam - using C++", "Size": "3.1 MB"}
    ]
    
    for file in studio_files:
        st.text(f"{file['Name']} - {file['Size']}")

# Main Content
tab1, tab2, tab3 = st.tabs(["Dashboard", "Scanner", "Reports"])

with tab1:
    # Metrics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        total_vulns = len(st.session_state.scan_results.get("vulnerabilities", [])) if st.session_state.scan_results else 0
        st.metric("Active Vulnerabilities", total_vulns)
    
    with col2:
        st.metric("Reports Generated", len(st.session_state.reports_list))
    
    with col3:
        st.metric("Backend Status", "✅ Online" if BACKEND_URL else "❌ Offline")
    
    # Recent Activity
    if st.session_state.scanning:
        st.info("🔄 Scan in progress...")
        progress_bar = st.progress(0)
        for i in range(100):
            time.sleep(0.01)
            progress_bar.progress(i + 1)
    
    elif st.session_state.scan_results:
        st.subheader("📊 Scan Results")
        vulnerabilities = st.session_state.scan_results.get("vulnerabilities", [])
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities):
                severity = vuln.get("severity", "medium")
                color = {
                    "critical": "#ef4444",
                    "high": "#f97316", 
                    "medium": "#eab308",
                    "low": "#10b981"
                }.get(severity, "#eab308")
                
                with st.expander(f"{vuln.get('type', 'Unknown')} - {severity.upper()}"):
                    st.write(f"**Target:** {vuln.get('target', 'N/A')}")
                    st.write(f"**Description:** {vuln.get('description', 'No description')}")
                    st.code(f"Payload: {vuln.get('payload', 'No payload')}")
        else:
            st.success("✅ No vulnerabilities found!")

with tab2:
    st.header("🚀 Website Vulnerability Scanner")
    
    col1, col2 = st.columns(2)
    with col1:
        scan_url = st.text_input("Website URL", value="http://testphp.vulnweb.com", key="scanner_url")
        scan_mode = st.selectbox("Scan Mode", ["Fast", "Full", "Deep"])
    
    with col2:
        st.write("### Scan Statistics")
        st.metric("Last Scan", "Success" if st.session_state.scan_results else "Never")
        st.metric("Vulnerabilities Found", len(st.session_state.scan_results.get("vulnerabilities", [])) if st.session_state.scan_results else 0)
    
    if st.button("🚀 START SCAN", use_container_width=True, type="primary"):
        if scan_url:
            with st.spinner("Scanning..."):
                result = scan_website(scan_url)
                if result["success"]:
                    st.session_state.scan_results = result["data"]
                    st.success("✅ Scan completed!")
                    st.rerun()
                else:
                    st.error(f"❌ {result['error']}")

with tab3:
    st.header("📋 Vulnerability Reports")
    
    if st.session_state.reports_list:
        for report in st.session_state.reports_list[:10]:  # Show first 10
            col1, col2 = st.columns([3, 1])
            with col1:
                st.write(f"**{report}**")
            with col2:
                if st.button("📥 Download", key=f"dl_{report}"):
                    with st.spinner("Downloading..."):
                        result = download_report(report)
                        if result["success"]:
                            b64 = base64.b64encode(result["content"]).decode()
                            href = f'<a href="data:application/octet-stream;base64,{b64}" download="{result["filename"]}">Click to download {result["filename"]}</a>'
                            st.markdown(href, unsafe_allow_html=True)
                        else:
                            st.error(result['error'])
    else:
        st.info("No reports available. Run a scan first!")

# Footer
st.divider()
st.caption(f"© 2026 Industrial Cybersecurity Dashboard | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
