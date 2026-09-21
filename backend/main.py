from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import socket
import ipaddress
import re
import uuid
import threading

from concurrent.futures import ThreadPoolExecutor, as_completed


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="ShadowScan",
    description="TCP Port Scanner with Service Detection and Risk Analysis",
    version="4.2"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# SCANNER SETTINGS
# ============================================================

MAX_WORKERS = 100
SOCKET_TIMEOUT = 0.5
BANNER_TIMEOUT = 1.0


# ============================================================
# ACTIVE SCANS
# ============================================================

scans = {}
scans_lock = threading.Lock()


# ============================================================
# COMMON SERVICES
# ============================================================

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP / FastAPI",
    8080: "HTTP"
}


# ============================================================
# RISK RULES
# ============================================================

RISK_RULES = {

    21: {
        "level": "HIGH",
        "score": 75,
        "reason": "FTP may transmit credentials and data without encryption.",
        "finding": "FTP service is exposed.",
        "recommendation": "Prefer SFTP or FTPS and restrict access to trusted networks."
    },

    22: {
        "level": "MEDIUM",
        "score": 40,
        "reason": "SSH provides remote access and should be securely configured.",
        "finding": "SSH remote administration service is exposed.",
        "recommendation": "Use key-based authentication, disable unnecessary access, and restrict trusted source IPs."
    },

    23: {
        "level": "CRITICAL",
        "score": 95,
        "reason": "Telnet provides remote access without modern transport encryption.",
        "finding": "Telnet remote access service is exposed.",
        "recommendation": "Disable Telnet and use SSH instead."
    },

    25: {
        "level": "MEDIUM",
        "score": 45,
        "reason": "SMTP exposure may require additional authentication and relay controls.",
        "finding": "SMTP mail service is exposed.",
        "recommendation": "Review relay restrictions, authentication, and mail transport security."
    },

    53: {
        "level": "MEDIUM",
        "score": 40,
        "reason": "DNS exposure should be reviewed for unnecessary external access.",
        "finding": "DNS service is exposed.",
        "recommendation": "Restrict DNS access and ensure recursive queries are not unnecessarily exposed."
    },

    80: {
        "level": "MEDIUM",
        "score": 45,
        "reason": "HTTP traffic is not encrypted by default.",
        "finding": "Unencrypted HTTP service is exposed.",
        "recommendation": "Prefer HTTPS and redirect HTTP traffic to encrypted communication."
    },

    110: {
        "level": "HIGH",
        "score": 70,
        "reason": "POP3 may expose authentication traffic when encryption is not configured.",
        "finding": "POP3 mail service is exposed.",
        "recommendation": "Use POP3S or another encrypted mail protocol."
    },

    143: {
        "level": "MEDIUM",
        "score": 50,
        "reason": "IMAP should use encrypted authentication and transport.",
        "finding": "IMAP mail service is exposed.",
        "recommendation": "Require TLS and secure authentication for mail access."
    },

    443: {
        "level": "LOW",
        "score": 15,
        "reason": "HTTPS normally provides encrypted web communication.",
        "finding": "HTTPS web service is exposed.",
        "recommendation": "Keep TLS configuration and server software updated."
    },

    3306: {
        "level": "HIGH",
        "score": 85,
        "reason": "Direct database exposure can increase attack surface.",
        "finding": "MySQL database service is exposed.",
        "recommendation": "Restrict database access to trusted application hosts or private networks."
    },

    5432: {
        "level": "HIGH",
        "score": 85,
        "reason": "Direct PostgreSQL exposure can increase attack surface.",
        "finding": "PostgreSQL database service is exposed.",
        "recommendation": "Restrict database access and avoid unnecessary public exposure."
    },

    6379: {
        "level": "CRITICAL",
        "score": 95,
        "reason": "Redis exposure can be dangerous when authentication and network controls are weak.",
        "finding": "Redis database service is exposed.",
        "recommendation": "Restrict Redis to trusted networks and enable appropriate authentication and access controls."
    },

    8000: {
        "level": "MEDIUM",
        "score": 45,
        "reason": "Application development ports may expose services that are not intended for public access.",
        "finding": "Application development service is exposed.",
        "recommendation": "Review whether the development service should be reachable from the network."
    },

    8080: {
        "level": "MEDIUM",
        "score": 45,
        "reason": "Alternative HTTP services should be reviewed for unnecessary exposure.",
        "finding": "Alternative HTTP service is exposed.",
        "recommendation": "Verify that the service is required and properly secured."
    }
}


# ============================================================
# DEFAULT RISK
# ============================================================

DEFAULT_RISK = {
    "level": "LOW",
    "score": 20,
    "reason": "Unknown service. Review the service before determining exposure risk.",
    "finding": "An unidentified service is exposed.",
    "recommendation": "Identify the service and verify that the port is intentionally accessible."
}


# ============================================================
# GET RISK
# ============================================================

def get_risk(port):
    return RISK_RULES.get(
        port,
        DEFAULT_RISK
    )


# ============================================================
# TARGET VALIDATION
# ============================================================

def validate_target(target):

    target = target.strip()

    if not target:
        return False, None, "Target cannot be empty."

    try:
        ipaddress.ip_address(target)

        return True, target, None

    except ValueError:
        pass

    hostname_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
    )

    if not re.match(
        hostname_pattern,
        target
    ):
        return (
            False,
            None,
            "Invalid IP address or hostname."
        )

    try:

        resolved_ip = socket.gethostbyname(
            target
        )

        return True, resolved_ip, None

    except socket.gaierror:

        return (
            False,
            None,
            "Unable to resolve the target hostname."
        )


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "message": "ShadowScan backend is running!",
        "status": "online",
        "version": "4.2"
    }


# ============================================================
# BANNER GRABBING
# ============================================================

def grab_banner(
    target,
    port
):

    banner = ""
    sock = None

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            BANNER_TIMEOUT
        )

        result = sock.connect_ex(
            (
                target,
                port
            )
        )

        if result != 0:
            return ""

        try:

            data = sock.recv(
                1024
            )

            if data:

                banner = data.decode(
                    "utf-8",
                    errors="ignore"
                ).strip()

        except socket.timeout:

            banner = ""

        except Exception:

            banner = ""

        # ----------------------------------------------------
        # HTTP banner request
        # ----------------------------------------------------

        if port in [
            80,
            443,
            8000,
            8080
        ]:

            try:

                request = (
                    "HEAD / HTTP/1.0\r\n"
                    "Host: "
                    + target
                    + "\r\n"
                    "\r\n"
                )

                sock.send(
                    request.encode()
                )

                data = sock.recv(
                    2048
                )

                if data:

                    banner = data.decode(
                        "utf-8",
                        errors="ignore"
                    ).strip()

            except Exception:

                pass

    except Exception:

        return ""

    finally:

        if sock:

            try:
                sock.close()
            except Exception:
                pass

    if banner:

        banner = banner.replace(
            "\r",
            ""
        )

        banner = banner.replace(
            "\n",
            " | "
        )

        banner = banner[:300]

    return banner


# ============================================================
# SCAN SINGLE PORT
# ============================================================

def scan_single_port(
    target,
    port
):

    sock = None

    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(
            SOCKET_TIMEOUT
        )

        result = sock.connect_ex(
            (
                target,
                port
            )
        )

        if result != 0:
            return None

        service = COMMON_SERVICES.get(
            port,
            "Unknown"
        )

        risk = get_risk(
            port
        )

        sock.close()
        sock = None

        banner = grab_banner(
            target,
            port
        )

        return {

            "port": port,

            "service": service,

            "banner": banner,

            "risk": risk["level"],

            "risk_score": risk["score"],

            "risk_reason": risk["reason"],

            "finding": risk["finding"],

            "recommendation": risk["recommendation"]

        }

    except socket.error:

        return None

    except Exception:

        return None

    finally:

        if sock:

            try:
                sock.close()
            except Exception:
                pass


# ============================================================
# GENERATE SECURITY FINDINGS
# ============================================================

def generate_security_findings(
    open_ports
):

    findings = []

    for port in open_ports:

        findings.append({

            "port": port["port"],

            "service": port["service"],

            "severity": port["risk"],

            "risk_score": port["risk_score"],

            "title": port["finding"],

            "description": port["risk_reason"],

            "recommendation": port["recommendation"]

        })

    # --------------------------------------------------------
    # Sort findings by severity
    # --------------------------------------------------------

    severity_order = {

        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4

    }

    findings.sort(
        key=lambda item:
        severity_order.get(
            item["severity"],
            5
        )
    )

    return findings


# ============================================================
# CALCULATE FINAL RESULTS
# ============================================================

def calculate_results(
    target,
    resolved_target,
    start_port,
    end_port,
    open_ports
):

    open_ports.sort(
        key=lambda item: item["port"]
    )

    ports_scanned = (
        end_port
        - start_port
        + 1
    )

    open_ports_count = len(
        open_ports
    )

    closed_ports = (
        ports_scanned
        - open_ports_count
    )

    # --------------------------------------------------------
    # Average risk
    # --------------------------------------------------------

    if open_ports:

        total_risk = sum(
            port["risk_score"]
            for port in open_ports
        )

        average_risk = (
            total_risk
            / open_ports_count
        )

    else:

        average_risk = 0

    # --------------------------------------------------------
    # Overall risk
    # --------------------------------------------------------

    if average_risk >= 80:

        overall_risk = "CRITICAL"

    elif average_risk >= 60:

        overall_risk = "HIGH"

    elif average_risk >= 30:

        overall_risk = "MEDIUM"

    else:

        overall_risk = "LOW"

    # --------------------------------------------------------
    # Risk counts
    # --------------------------------------------------------

    risk_counts = {

        "LOW": 0,

        "MEDIUM": 0,

        "HIGH": 0,

        "CRITICAL": 0

    }

    for port in open_ports:

        risk_level = port["risk"]

        if risk_level in risk_counts:

            risk_counts[
                risk_level
            ] += 1

    # --------------------------------------------------------
    # Security findings
    # --------------------------------------------------------

    security_findings = (
        generate_security_findings(
            open_ports
        )
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {

        "target": target,

        "resolved_target": resolved_target,

        "start_port": start_port,

        "end_port": end_port,

        "ports_scanned": ports_scanned,

        "open_ports_count": open_ports_count,

        "closed_ports": closed_ports,

        "average_risk_score": round(
            average_risk,
            2
        ),

        "overall_risk": overall_risk,

        "risk_counts": risk_counts,

        "security_findings": security_findings,

        "scan_status": "completed",

        "open_ports": open_ports

    }


# ============================================================
# BACKGROUND SCAN
# ============================================================

def run_scan(
    scan_id,
    target,
    resolved_target,
    start_port,
    end_port
):

    ports = list(
        range(
            start_port,
            end_port + 1
        )
    )

    total_ports = len(
        ports
    )

    open_ports = []

    completed_ports = 0

    # --------------------------------------------------------
    # Get cancellation event
    # --------------------------------------------------------

    with scans_lock:

        cancel_event = scans[
            scan_id
        ][
            "cancel_event"
        ]

        if not cancel_event.is_set():

            scans[
                scan_id
            ][
                "status"
            ] = "scanning"

        scans[
            scan_id
        ][
            "total_ports"
        ] = total_ports

        scans[
            scan_id
        ][
            "ports_scanned"
        ] = 0

        scans[
            scan_id
        ][
            "open_ports"
        ] = 0

        scans[
            scan_id
        ][
            "progress"
        ] = 0

    # --------------------------------------------------------
    # Concurrent scan
    # --------------------------------------------------------

    try:

        with ThreadPoolExecutor(
            max_workers=MAX_WORKERS
        ) as executor:

            futures = {

                executor.submit(
                    scan_single_port,
                    resolved_target,
                    port
                ): port

                for port in ports

            }

            for future in as_completed(
                futures
            ):

                # ------------------------------------------------
                # Check cancellation
                # ------------------------------------------------

                if cancel_event.is_set():

                    with scans_lock:

                        scans[
                            scan_id
                        ][
                            "status"
                        ] = "cancelled"

                    executor.shutdown(
                        wait=False,
                        cancel_futures=True
                    )

                    return

                try:

                    result = future.result()

                    if result is not None:

                        open_ports.append(
                            result
                        )

                except Exception:

                    pass

                completed_ports += 1

                progress = int(
                    (
                        completed_ports
                        / total_ports
                    ) * 100
                )

                # ------------------------------------------------
                # Update live progress
                # ------------------------------------------------

                with scans_lock:

                    scans[
                        scan_id
                    ][
                        "ports_scanned"
                    ] = completed_ports

                    scans[
                        scan_id
                    ][
                        "open_ports"
                    ] = len(
                        open_ports
                    )

                    scans[
                        scan_id
                    ][
                        "progress"
                    ] = progress

        # ----------------------------------------------------
        # Check cancellation before final result
        # ----------------------------------------------------

        if cancel_event.is_set():

            with scans_lock:

                scans[
                    scan_id
                ][
                    "status"
                ] = "cancelled"

            return

        # ----------------------------------------------------
        # Calculate final result
        # ----------------------------------------------------

        result = calculate_results(

            target,

            resolved_target,

            start_port,

            end_port,

            open_ports

        )

        # ----------------------------------------------------
        # Store result
        # ----------------------------------------------------

        with scans_lock:

            scans[
                scan_id
            ][
                "status"
            ] = "completed"

            scans[
                scan_id
            ][
                "progress"
            ] = 100

            scans[
                scan_id
            ][
                "result"
            ] = result

    except Exception as error:

        with scans_lock:

            scans[
                scan_id
            ][
                "status"
            ] = "failed"

            scans[
                scan_id
            ][
                "error"
            ] = str(error)


# ============================================================
# START SCAN
# ============================================================

@app.post("/scan")
def start_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 100
):

    # --------------------------------------------------------
    # Validate target
    # --------------------------------------------------------

    valid, resolved_target, error = (
        validate_target(target)
    )

    if not valid:

        return {

            "error": error,

            "target": target,

            "scan_status": "failed"

        }

    # --------------------------------------------------------
    # Validate ports
    # --------------------------------------------------------

    if start_port < 1:

        return {

            "error":
                "Start port must be between 1 and 65535.",

            "scan_status": "failed"

        }

    if end_port > 65535:

        return {

            "error":
                "End port must be between 1 and 65535.",

            "scan_status": "failed"

        }

    if start_port > end_port:

        return {

            "error":
                "Invalid port range.",

            "scan_status": "failed"

        }

    # --------------------------------------------------------
    # Generate scan ID
    # --------------------------------------------------------

    scan_id = str(
        uuid.uuid4()
    )

    # --------------------------------------------------------
    # Create cancellation event
    # --------------------------------------------------------

    cancel_event = threading.Event()

    # --------------------------------------------------------
    # Create scan record
    # --------------------------------------------------------

    with scans_lock:

        scans[
            scan_id
        ] = {

            "scan_id":
                scan_id,

            "target":
                target,

            "resolved_target":
                resolved_target,

            "start_port":
                start_port,

            "end_port":
                end_port,

            "status":
                "starting",

            "progress":
                0,

            "total_ports":
                (
                    end_port
                    - start_port
                    + 1
                ),

            "ports_scanned":
                0,

            "open_ports":
                0,

            "cancel_event":
                cancel_event

        }

    # --------------------------------------------------------
    # Start background thread
    # --------------------------------------------------------

    scan_thread = threading.Thread(

        target=run_scan,

        args=(

            scan_id,

            target,

            resolved_target,

            start_port,

            end_port

        ),

        daemon=True

    )

    scan_thread.start()

    # --------------------------------------------------------
    # Return scan ID
    # --------------------------------------------------------

    return {

        "scan_id":
            scan_id,

        "target":
            target,

        "start_port":
            start_port,

        "end_port":
            end_port,

        "status":
            "started"

    }


# ============================================================
# CANCEL SCAN
# ============================================================

@app.post("/scan/{scan_id}/cancel")
def cancel_scan(
    scan_id: str
):

    with scans_lock:

        scan = scans.get(
            scan_id
        )

        if scan is None:

            return {

                "error":
                    "Scan ID not found.",

                "status":
                    "failed"

            }

        current_status = scan[
            "status"
        ]

        # ----------------------------------------------------
        # Already completed
        # ----------------------------------------------------

        if current_status == "completed":

            return {

                "scan_id":
                    scan_id,

                "status":
                    "completed",

                "message":
                    "Scan has already completed."

            }

        # ----------------------------------------------------
        # Already cancelled
        # ----------------------------------------------------

        if current_status == "cancelled":

            return {

                "scan_id":
                    scan_id,

                "status":
                    "cancelled",

                "message":
                    "Scan is already cancelled."

            }

        # ----------------------------------------------------
        # Failed scan
        # ----------------------------------------------------

        if current_status == "failed":

            return {

                "scan_id":
                    scan_id,

                "status":
                    "failed",

                "message":
                    "Scan has already failed."

            }

        # ----------------------------------------------------
        # Request cancellation
        # ----------------------------------------------------

        scan[
            "cancel_event"
        ].set()

        scan[
            "status"
        ] = "cancelling"

        return {

            "scan_id":
                scan_id,

            "status":
                "cancelling",

            "message":
                "Scan cancellation requested."

        }


# ============================================================
# SCAN STATUS
# ============================================================

@app.get("/scan/{scan_id}/status")
def get_scan_status(
    scan_id: str
):

    with scans_lock:

        scan = scans.get(
            scan_id
        )

        if scan is None:

            return {

                "error":
                    "Scan ID not found.",

                "status":
                    "failed"

            }

        return {

            "scan_id":
                scan["scan_id"],

            "target":
                scan["target"],

            "status":
                scan["status"],

            "progress":
                scan["progress"],

            "total_ports":
                scan["total_ports"],

            "ports_scanned":
                scan["ports_scanned"],

            "open_ports":
                scan["open_ports"],

            "error":
                scan.get("error")

        }


# ============================================================
# SCAN RESULT
# ============================================================

@app.get("/scan/{scan_id}/result")
def get_scan_result(
    scan_id: str
):

    with scans_lock:

        scan = scans.get(
            scan_id
        )

        if scan is None:

            return {

                "error":
                    "Scan ID not found.",

                "scan_status":
                    "failed"

            }

        # ----------------------------------------------------
        # Cancelled
        # ----------------------------------------------------

        if scan[
            "status"
        ] == "cancelled":

            return {

                "scan_id":
                    scan_id,

                "scan_status":
                    "cancelled",

                "progress":
                    scan["progress"],

                "message":
                    "Scan was cancelled."

            }

        # ----------------------------------------------------
        # Still running
        # ----------------------------------------------------

        if scan[
            "status"
        ] != "completed":

            return {

                "scan_id":
                    scan_id,

                "scan_status":
                    scan["status"],

                "progress":
                    scan["progress"],

                "message":
                    "Scan is still running."

            }

        # ----------------------------------------------------
        # Completed result
        # ----------------------------------------------------

        return scan[
            "result"
        ]