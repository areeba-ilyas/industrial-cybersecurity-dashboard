import streamlit as st
import pandas as pd
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# Page configuration
st.set_page_config(
    page_title="Industrial Cybersecurity Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #374151;
        font-weight: 600;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
    }
    .vulnerability-card {
        background-color: #F9FAFB;
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 5px solid;
    }
    .critical {
        border-left-color: #DC2626;
        background-color: #FEF2F2;
    }
    .high {
        border-left-color: #EA580C;
        background-color: #FFF7ED;
    }
    .medium {
        border-left-color: #F59E0B;
        background-color: #FFFBEB;
    }
    .severity-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 0.8rem;
        display: inline-block;
    }
    .metric-card {
        background-color: #F8FAFC;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .countermeasure-box {
        background-color: #EFF6FF;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        border-left: 4px solid #3B82F6;
    }
    .footer {
        margin-top: 3rem;
        padding-top: 1rem;
        border-top: 1px solid #E5E7EB;
        color: #6B7280;
        font-size: 0.9rem;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

# App Title
st.markdown('<p class="main-header">🛡️ Industrial Cybersecurity Vulnerability Dashboard</p>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/5/5a/Tenable_logo.svg/2560px-Tenable_logo.svg.png", width=200)
    st.markdown("---")
    
    st.markdown("### Audit Information")
    audit_date = st.date_input("Audit Date", datetime(2026, 2, 7))
    security_level = st.selectbox("Security Level Target", ["SL-1", "SL-2", "SL-3", "SL-4"], index=1)
    
    st.markdown("---")
    st.markdown("### System Under Consideration")
    st.info("Automated assessment of web-based interface controls to verify adherence to IEC 62443-3-3 security requirements.")
    
    st.markdown("---")
    st.markdown("### Filter Vulnerabilities")
    severity_filter = st.multiselect(
        "Severity Level",
        ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        default=["CRITICAL", "HIGH", "MEDIUM"]
    )
    
    st.markdown("---")
    st.caption("Dashboard v1.0 • IEC 62443-3-3 Compliance")

# Vulnerability Data
vulnerabilities_data = [
    {
        "id": "VULN-001",
        "finding": "SQL Injection (SQLI)",
        "severity": "HIGH",
        "severity_level": 3,
        "requirement": "FR 3 - System Integrity",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=",
        "payload": '"Payload Triangulated',
        "countermeasures": [
            "IMMEDIATELY ISOLATE AND RESTRICT ALL network ingress/egress to the vulnerable Production Zone segment.",
            "MANDATORY REFACTOR application code to enforce parameterized queries and stringent input validation.",
            "INITIATE an URGENT FORENSIC IMAGE and enable comprehensive event logging."
        ],
        "status": "OPEN",
        "discovered": "2026-02-07",
        "affected_assets": 3
    },
    {
        "id": "VULN-002",
        "finding": "Remote Code Execution (RCE)",
        "severity": "CRITICAL",
        "severity_level": 4,
        "requirement": "FR 3 - System Integrity",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=",
        "payload": '"@print(md5(zigoo))" & $(@print(md5(zigoo)))',
        "countermeasures": [
            "IMMEDIATELY ISOLATE all affected production systems into a secure quarantine network.",
            "FORCE a global password reset for all associated operator and service accounts.",
            "INITIATE a full forensic analysis on isolated systems."
        ],
        "status": "OPEN",
        "discovered": "2026-02-07",
        "affected_assets": 5
    },
    {
        "id": "VULN-003",
        "finding": "Cross-Site Scripting (XSS)",
        "severity": "MEDIUM",
        "severity_level": 2,
        "requirement": "FR 4 - Data Confidentiality",
        "target": "http://testphp.vulnweb.com/listproducts.php?cat=",
        "payload": '<script>alert(1)</script>',
        "countermeasures": [
            "IMMEDIATELY RESTRICT network access to the compromised production application.",
            "MANDATORY REFACTOR affected code, implementing strict input validation.",
            "EXECUTE a full forensic analysis on the host."
        ],
        "status": "OPEN",
        "discovered": "2026-02-07",
        "affected_assets": 2
    }
]

# Filter vulnerabilities based on sidebar selection
filtered_vulns = [v for v in vulnerabilities_data if v["severity"] in severity_filter]

# Metrics Row
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("Total Vulnerabilities", len(vulnerabilities_data))
    st.markdown('</div>', unsafe_allow_html=True)

with col2:
    critical_count = len([v for v in vulnerabilities_data if v["severity"] == "CRITICAL"])
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("Critical", critical_count, delta=f"{critical_count} open")
    st.markdown('</div>', unsafe_allow_html=True)

with col3:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("Affected Assets", sum([v["affected_assets"] for v in vulnerabilities_data]))
    st.markdown('</div>', unsafe_allow_html=True)

with col4:
    st.markdown('<div class="metric-card">', unsafe_allow_html=True)
    st.metric("Compliance Status", "65%", delta="-15% from target")
    st.markdown('</div>', unsafe_allow_html=True)

# Charts Row
col1, col2 = st.columns(2)

with col1:
    st.markdown('<p class="sub-header">📊 Vulnerability Distribution by Severity</p>', unsafe_allow_html=True)
    
    severity_counts = {
        "CRITICAL": len([v for v in vulnerabilities_data if v["severity"] == "CRITICAL"]),
        "HIGH": len([v for v in vulnerabilities_data if v["severity"] == "HIGH"]),
        "MEDIUM": len([v for v in vulnerabilities_data if v["severity"] == "MEDIUM"]),
        "LOW": len([v for v in vulnerabilities_data if v["severity"] == "LOW"])
    }
    
    colors = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#F59E0B", "LOW": "#10B981"}
    
    fig = go.Figure(data=[go.Pie(
        labels=list(severity_counts.keys()),
        values=list(severity_counts.values()),
        hole=0.4,
        marker_colors=[colors[sev] for sev in severity_counts.keys()]
    )])
    
    fig.update_layout(
        height=300,
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=True
    )
    
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.markdown('<p class="sub-header">📈 Affected Assets by Vulnerability</p>', unsafe_allow_html=True)
    
    vuln_names = [v["finding"] for v in vulnerabilities_data]
    asset_counts = [v["affected_assets"] for v in vulnerabilities_data]
    severity_colors = [colors[v["severity"]] for v in vulnerabilities_data]
    
    fig2 = go.Figure(data=[
        go.Bar(
            x=vuln_names,
            y=asset_counts,
            marker_color=severity_colors,
            text=asset_counts,
            textposition='auto'
        )
    ])
    
    fig2.update_layout(
        height=300,
        margin=dict(l=10, r=10, t=10, b=30),
        xaxis_title="Vulnerability",
        yaxis_title="Affected Assets"
    )
    
    st.plotly_chart(fig2, use_container_width=True)

# Main Content - Vulnerability Details
st.markdown('<p class="sub-header">🔍 Vulnerability Analysis Details</p>', unsafe_allow_html=True)

if not filtered_vulns:
    st.warning("No vulnerabilities match the selected filters.")
else:
    for vuln in filtered_vulns:
        # Determine CSS class based on severity
        severity_class = ""
        if vuln["severity"] == "CRITICAL":
            severity_class = "critical"
            badge_color = "#DC2626"
        elif vuln["severity"] == "HIGH":
            severity_class = "high"
            badge_color = "#EA580C"
        elif vuln["severity"] == "MEDIUM":
            severity_class = "medium"
            badge_color = "#F59E0B"
        else:
            badge_color = "#10B981"
        
        with st.container():
            st.markdown(f'<div class="vulnerability-card {severity_class}">', unsafe_allow_html=True)
            
            # Header row
            col1, col2, col3 = st.columns([3, 1, 1])
            
            with col1:
                st.markdown(f"### {vuln['finding']}")
            
            with col2:
                st.markdown(f'<span class="severity-badge" style="background-color: {badge_color}; color: white;">{vuln["severity"]}</span>', unsafe_allow_html=True)
            
            with col3:
                st.markdown(f"**ID:** {vuln['id']}")
            
            # Details
            st.markdown(f"**Requirement Reference:** {vuln['requirement']}")
            st.markdown(f"**Target Component:** `{vuln['target']}`")
            st.markdown(f"**Payload:** `{vuln['payload']}`")
            
            # Countermeasures
            st.markdown("**Required Engineering Countermeasures:**")
            for i, cm in enumerate(vuln['countermeasures'], 1):
                st.markdown(f'<div class="countermeasure-box">', unsafe_allow_html=True)
                st.markdown(f"**{i}.** {cm}")
                st.markdown('</div>', unsafe_allow_html=True)
            
            # Footer info
            col1, col2, col3 = st.columns(3)
            with col1:
                st.caption(f"Discovered: {vuln['discovered']}")
            with col2:
                st.caption(f"Affected Assets: {vuln['affected_assets']}")
            with col3:
                status_color = "#DC2626" if vuln['status'] == "OPEN" else "#10B981"
                st.markdown(f'<span style="color: {status_color}; font-weight: 600;">Status: {vuln["status"]}</span>', unsafe_allow_html=True)
            
            st.markdown('</div>', unsafe_allow_html=True)

# Compliance Information
st.markdown('<p class="sub-header">📋 IEC 62443-3-3 Compliance Status</p>', unsafe_allow_html=True)

compliance_data = {
    "Requirement": ["FR 3 - System Integrity", "FR 4 - Data Confidentiality", 
                   "SD.04.01 - Secure Development", "SD.06.01 - Logging & Monitoring"],
    "Status": ["NON-COMPLIANT", "PARTIALLY COMPLIANT", "NON-COMPLIANT", "NOT IMPLEMENTED"],
    "Vulnerabilities": [2, 1, 2, 0]
}

compliance_df = pd.DataFrame(compliance_data)
st.dataframe(
    compliance_df,
    column_config={
        "Status": st.column_config.TextColumn(
            "Status",
            help="Compliance status",
            width="medium"
        ),
        "Vulnerabilities": st.column_config.NumberColumn(
            "Vulnerabilities",
            help="Number of related vulnerabilities",
            width="small"
        )
    },
    hide_index=True,
    use_container_width=True
)

# Footer
st.markdown('<div class="footer">', unsafe_allow_html=True)
st.markdown("**Industrial Cybersecurity Audit Dashboard** • Security Level Target: SL-2 • IEC 62443-3-3 Compliance Assessment")
st.markdown(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} • For authorized personnel only")
st.markdown('</div>', unsafe_allow_html=True)
