from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socket


# ============================================================
# SHADOWSCAN API
# ============================================================

app = FastAPI(
    title="ShadowScan",
    description="TCP Port Scanner with Service Detection",
    version="2.0"
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
# HOME ROUTE
# ============================================================

@app.get("/")
def home():

    return {
        "message": "ShadowScan backend is running!",
        "status": "online"
    }


# ============================================================
# BANNER GRABBING
# ============================================================

def grab_banner(
    target,
    port
):

    banner = ""


    try:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(1)


        # ----------------------------------------------------
        # CONNECT
        # ----------------------------------------------------

        result = sock.connect_ex(
            (target, port)
        )


        if result != 0:

            sock.close()

            return ""


        # ----------------------------------------------------
        # SOME SERVICES SEND A BANNER
        # IMMEDIATELY AFTER CONNECTION
        # ----------------------------------------------------

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


        # ----------------------------------------------------
        # HTTP SERVICES
        # ----------------------------------------------------

        if port in [80, 443, 8000, 8080]:

            try:

                request = (
                    "HEAD / HTTP/1.0\r\n"
                    "Host: " + target + "\r\n"
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


        sock.close()


    except Exception:

        return ""


    # ========================================================
    # CLEAN BANNER
    # ========================================================

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
# PORT SCANNER
# ============================================================

@app.get("/scan")
def scan_ports(
    target: str,
    start_port: int = 1,
    end_port: int = 100
):

    open_ports = []


    # ========================================================
    # VALIDATE PORT RANGE
    # ========================================================

    if start_port < 1:

        start_port = 1


    if end_port > 65535:

        end_port = 65535


    if start_port > end_port:

        return {
            "error": "Invalid port range"
        }


    # ========================================================
    # SCAN PORTS
    # ========================================================

    for port in range(
        start_port,
        end_port + 1
    ):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )


        sock.settimeout(
            0.5
        )


        try:

            result = sock.connect_ex(
                (target, port)
            )


            if result == 0:

                service = COMMON_SERVICES.get(
                    port,
                    "Unknown"
                )


                # ------------------------------------------------
                # BANNER GRABBING
                # ------------------------------------------------

                banner = grab_banner(
                    target,
                    port
                )


                open_ports.append({

                    "port": port,

                    "service": service,

                    "banner": banner

                })


        except socket.error:

            pass


        finally:

            sock.close()


    # ========================================================
    # STATISTICS
    # ========================================================

    ports_scanned = (
        end_port -
        start_port +
        1
    )


    open_ports_count =
        len(open_ports)


    closed_ports = (
        ports_scanned -
        open_ports_count
    )


    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "target": target,

        "start_port": start_port,

        "end_port": end_port,

        "ports_scanned": ports_scanned,

        "open_ports_count": open_ports_count,

        "closed_ports": closed_ports,

        "scan_status": "completed",

        "open_ports": open_ports
    }