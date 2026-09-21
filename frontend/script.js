// ============================================================
// SHADOWSCAN - FRONTEND JAVASCRIPT
// ============================================================


// ============================================================
// DOM ELEMENTS
// ============================================================

const scanButton =
    document.getElementById("scanButton");

const output =
    document.getElementById("output");

const progressFill =
    document.getElementById("progressFill");

const progressText =
    document.getElementById("progressText");

const resultsBody =
    document.getElementById("resultsBody");

const portsScannedElement =
    document.getElementById("portsScanned");

const openPortsElement =
    document.getElementById("openPorts");

const riskLevelElement =
    document.getElementById("riskLevel");

const historyBody =
    document.getElementById("historyBody");

const securityFindings =
    document.getElementById("securityFindings");

const clearHistoryButton =
    document.getElementById("clearHistory");

const targetInput =
    document.getElementById("target");

const startPortInput =
    document.getElementById("startPort");

const endPortInput =
    document.getElementById("endPort");


// ============================================================
// BACKEND URL
// ============================================================

const BACKEND_URL =
    "http://127.0.0.1:8000";


// ============================================================
// RISK SCORE WEIGHTS
// ============================================================

const RISK_POINTS = {

    21: 15,      // FTP
    22: 5,       // SSH
    23: 30,      // Telnet
    25: 10,      // SMTP
    53: 5,       // DNS
    80: 5,       // HTTP
    110: 10,     // POP3
    143: 10,     // IMAP
    443: 0,      // HTTPS
    3306: 20,    // MySQL
    5432: 20,    // PostgreSQL
    6379: 20,    // Redis
    8000: 5,     // FastAPI
    8080: 5      // HTTP alternate
};


// ============================================================
// SCAN BUTTON
// ============================================================

scanButton.addEventListener(
    "click",
    startScan
);


// ============================================================
// START SCAN
// ============================================================

async function startScan() {

    const target =
        targetInput.value.trim();

    const startPort =
        parseInt(startPortInput.value);

    const endPort =
        parseInt(endPortInput.value);


    // ========================================================
    // VALIDATION
    // ========================================================

    if (!target) {

        alert(
            "Please enter a target."
        );

        return;
    }


    if (
        isNaN(startPort) ||
        isNaN(endPort)
    ) {

        alert(
            "Please enter valid port numbers."
        );

        return;
    }


    if (
        startPort < 1 ||
        endPort > 65535
    ) {

        alert(
            "Port numbers must be between 1 and 65535."
        );

        return;
    }


    if (
        startPort > endPort
    ) {

        alert(
            "Start port cannot be greater than end port."
        );

        return;
    }


    // ========================================================
    // RESET UI
    // ========================================================

    scanButton.disabled =
        true;

    scanButton.innerText =
        "⚡ SCANNING...";


    progressFill.style.width =
        "0%";

    progressText.innerText =
        "0% — INITIALIZING";


    resultsBody.innerHTML =
        "";


    portsScannedElement.innerText =
        "0";

    openPortsElement.innerText =
        "0";

    riskLevelElement.innerText =
        "—";


    // ========================================================
    // RESET SECURITY FINDINGS
    // ========================================================

    if (securityFindings) {

        securityFindings.innerHTML = `
            <div class="finding-empty">
                Analyzing detected services...
            </div>
        `;
    }


    // ========================================================
    // TERMINAL
    // ========================================================

    output.innerHTML = `
        > INITIALIZING SHADOWSCAN...<br>
        > TARGET: ${target}<br>
        > PORT RANGE: ${startPort} - ${endPort}<br>
        > CONNECTING TO SCANNER ENGINE...
    `;


    // ========================================================
    // PROGRESS ANIMATION
    // ========================================================

    let progress =
        0;


    const progressInterval =
        setInterval(
            () => {

                if (progress < 90) {

                    progress += 5;

                    progressFill.style.width =
                        `${progress}%`;

                    progressText.innerText =
                        `${progress}% — SCANNING`;
                }

            },
            150
        );


    // ========================================================
    // API REQUEST
    // ========================================================

    try {

        const url =
            `${BACKEND_URL}/scan` +
            `?target=${encodeURIComponent(target)}` +
            `&start_port=${startPort}` +
            `&end_port=${endPort}`;


        const response =
            await fetch(url);


        if (!response.ok) {

            throw new Error(
                `Server returned ${response.status}`
            );
        }


        const data =
            await response.json();


        // ====================================================
        // STOP PROGRESS
        // ====================================================

        clearInterval(
            progressInterval
        );


        progressFill.style.width =
            "100%";

        progressText.innerText =
            "100% — SCAN COMPLETE";


        // ====================================================
        // BACKEND ERROR
        // ====================================================

        if (data.error) {

            throw new Error(
                data.error
            );
        }


        // ====================================================
        // UPDATE STATISTICS
        // ====================================================

        portsScannedElement.innerText =
            data.ports_scanned;

        openPortsElement.innerText =
            data.open_ports_count;


        // ====================================================
        // CALCULATE RISK SCORE
        // ====================================================

        const riskData =
            calculateRiskScore(
                data.open_ports
            );


        riskLevelElement.innerText =
            riskData.level;


        // ====================================================
        // DISPLAY RESULTS
        // ====================================================

        displayResults(
            data.open_ports
        );


        // ====================================================
        // DISPLAY SECURITY FINDINGS
        // ========================================================

        if (
            !data.open_ports ||
            data.open_ports.length === 0
        ) {

            if (securityFindings) {

                securityFindings.innerHTML = `
                    <div class="finding-empty">
                        No security findings detected.
                    </div>
                `;
            }

        } else {

            for (
                const portInfo
                of data.open_ports
            ) {

                const port =
                    portInfo.port;

                const service =
                    portInfo.service ||
                    "Unknown";


                addSecurityFinding(
                    port,
                    service
                );
            }
        }


        // ====================================================
        // TERMINAL SUCCESS
        // ====================================================

        output.innerHTML += `
            <br>
            > SCAN COMPLETED SUCCESSFULLY_<br>
            > PORTS SCANNED: ${data.ports_scanned}<br>
            > OPEN PORTS: ${data.open_ports_count}<br>
            > CLOSED PORTS: ${data.closed_ports}<br>
            > SECURITY SCORE: ${riskData.score}/100<br>
            > RISK LEVEL: ${riskData.level}
        `;


        // ====================================================
        // SAVE HISTORY
        // ====================================================

        saveScanHistory({

            time:
                new Date().toLocaleString(),

            target:
                target,

            range:
                `${startPort}-${endPort}`,

            open:
                data.open_ports_count,

            risk:
                riskData.level,

            score:
                riskData.score
        });


        displayHistory();


    } catch (error) {

        // ====================================================
        // STOP PROGRESS
        // ====================================================

        clearInterval(
            progressInterval
        );


        progressFill.style.width =
            "100%";

        progressText.innerText =
            "SCAN FAILED";


        // ====================================================
        // ERROR MESSAGE
        // ====================================================

        output.innerHTML += `
            <br>
            > ERROR: ${error.message}<br>
            > CHECK BACKEND CONNECTION.
        `;


        console.error(
            "ShadowScan Error:",
            error
        );


        alert(
            "Scan failed. Make sure the ShadowScan backend is running."
        );


    } finally {

        // ====================================================
        // RESTORE BUTTON
        // ====================================================

        scanButton.disabled =
            false;

        scanButton.innerText =
            "⚡ INITIATE SCAN";
    }
}


// ============================================================
// DISPLAY RESULTS
// ============================================================

function displayResults(
    openPorts
) {

    resultsBody.innerHTML =
        "";


    if (
        !openPorts ||
        openPorts.length === 0
    ) {

        const row =
            document.createElement(
                "tr"
            );


        row.innerHTML = `
            <td colspan="4">
                No open ports detected.
            </td>
        `;


        resultsBody.appendChild(
            row
        );

        return;
    }


    for (
        const portInfo
        of openPorts
    ) {

        const port =
            portInfo.port;

        const service =
            portInfo.service ||
            "Unknown";


        const risk =
            getPortRisk(
                port
            );


        const row =
            document.createElement(
                "tr"
            );


        row.innerHTML = `
            <td>
                ${port}
            </td>

            <td>
                <span class="status-open">
                    OPEN
                </span>
            </td>

            <td>
                ${service}
            </td>

            <td>
                <span class="${getRiskClass(risk)}">
                    ${risk}
                </span>
            </td>
        `;


        resultsBody.appendChild(
            row
        );
    }
}


// ============================================================
// PORT RISK
// ============================================================

function getPortRisk(
    port
) {

    if (
        port === 23
    ) {

        return "HIGH";
    }


    if (
        port === 21 ||
        port === 25 ||
        port === 110 ||
        port === 143 ||
        port === 3306 ||
        port === 5432 ||
        port === 6379
    ) {

        return "MEDIUM";
    }


    if (
        port === 22 ||
        port === 80 ||
        port === 8080
    ) {

        return "LOW";
    }


    return "INFO";
}


// ============================================================
// RISK CSS CLASS
// ============================================================

function getRiskClass(
    risk
) {

    if (
        risk === "HIGH"
    ) {

        return "risk-high";
    }


    if (
        risk === "MEDIUM"
    ) {

        return "risk-medium";
    }


    if (
        risk === "LOW"
    ) {

        return "risk-low";
    }


    return "";
}


// ============================================================
// RISK SCORE 2.0
// ============================================================

function calculateRiskScore(
    openPorts
) {

    if (
        !openPorts ||
        openPorts.length === 0
    ) {

        return {
            score: 0,
            level: "LOW"
        };
    }


    let score =
        0;


    // ========================================================
    // ADD POINTS FOR EACH OPEN SERVICE
    // ========================================================

    for (
        const portInfo
        of openPorts
    ) {

        const port =
            portInfo.port;


        const points =
            RISK_POINTS[port] || 3;


        score += points;
    }


    // ========================================================
    // CAP SCORE
    // ========================================================

    if (
        score > 100
    ) {

        score = 100;
    }


    // ========================================================
    // DETERMINE RISK LEVEL
    // ========================================================

    let level =
        "LOW";


    if (
        score >= 60
    ) {

        level =
            "HIGH";

    } else if (
        score >= 30
    ) {

        level =
            "MEDIUM";

    } else {

        level =
            "LOW";
    }


    return {
        score: score,
        level: level
    };
}


// ============================================================
// SECURITY FINDINGS
// ============================================================

function addSecurityFinding(
    port,
    service
) {

    if (!securityFindings) {

        return;
    }


    // --------------------------------------------------------
    // REMOVE EMPTY MESSAGE
    // --------------------------------------------------------

    const emptyMessage =
        securityFindings.querySelector(
            ".finding-empty"
        );


    if (emptyMessage) {

        emptyMessage.remove();
    }


    let title =
        "";

    let description =
        "";

    let severity =
        "info";

    let icon =
        "🔵";


    // ========================================================
    // SERVICE ANALYSIS
    // ========================================================

    switch (port) {


        case 21:

            title =
                "FTP service detected";

            description =
                "FTP is used for file transfer. " +
                "Traditional FTP does not encrypt traffic by default. " +
                "Review whether secure alternatives such as SFTP are available.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 22:

            title =
                "SSH service detected";

            description =
                "SSH provides remote administration. " +
                "Verify strong authentication, disable unnecessary access, " +
                "and restrict the service to authorized users.";

            severity =
                "low";

            icon =
                "🟢";

            break;


        case 23:

            title =
                "Telnet service detected";

            description =
                "Telnet is a legacy remote-access protocol that does not " +
                "provide modern encrypted communication. Consider replacing " +
                "it with SSH.";

            severity =
                "high";

            icon =
                "🔴";

            break;


        case 25:

            title =
                "SMTP service detected";

            description =
                "An email service is reachable on this port. " +
                "Review mail-server configuration, authentication, " +
                "and access restrictions.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 53:

            title =
                "DNS service detected";

            description =
                "A DNS service is reachable. Review whether the service " +
                "is intended to be publicly accessible and properly configured.";

            severity =
                "low";

            icon =
                "🟢";

            break;


        case 80:

            title =
                "HTTP web service detected";

            description =
                "An HTTP web service is reachable. " +
                "Review the application and consider HTTPS for protected communication.";

            severity =
                "low";

            icon =
                "🟢";

            break;


        case 110:

            title =
                "POP3 service detected";

            description =
                "POP3 is commonly used for email retrieval. " +
                "Review whether encrypted email access is configured.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 143:

            title =
                "IMAP service detected";

            description =
                "An IMAP email service is reachable. " +
                "Review authentication and encrypted transport settings.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 443:

            title =
                "HTTPS service detected";

            description =
                "An HTTPS web service is reachable. " +
                "Verify TLS configuration, certificates, and application security.";

            severity =
                "info";

            icon =
                "🔵";

            break;


        case 3306:

            title =
                "MySQL database detected";

            description =
                "A MySQL database service is reachable. " +
                "Database services should normally be restricted to authorized systems.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 5432:

            title =
                "PostgreSQL database detected";

            description =
                "A PostgreSQL database service is reachable. " +
                "Review network restrictions and authentication controls.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 6379:

            title =
                "Redis service detected";

            description =
                "A Redis service is reachable. " +
                "Review authentication and network-access controls.";

            severity =
                "medium";

            icon =
                "🟠";

            break;


        case 8000:

            title =
                "FastAPI / HTTP service detected";

            description =
                "A web API service is reachable on port 8000. " +
                "Review API authentication, exposed endpoints, " +
                "and access controls.";

            severity =
                "info";

            icon =
                "🔵";

            break;


        case 8080:

            title =
                "HTTP service detected";

            description =
                "An HTTP service is reachable on port 8080. " +
                "Review the application configuration and access controls.";

            severity =
                "low";

            icon =
                "🟢";

            break;


        default:

            title =
                `${service} service detected`;

            description =
                `Port ${port} is open and associated with ${service}. ` +
                "Review whether this service needs to be accessible.";

            severity =
                "info";

            icon =
                "🔵";
    }


    // ========================================================
    // CREATE FINDING
    // ========================================================

    const finding =
        document.createElement(
            "div"
        );


    finding.className =
        `finding finding-${severity}`;


    finding.innerHTML = `
        <div class="finding-title">

            <span class="finding-icon">
                ${icon}
            </span>

            ${title}

        </div>

        <div class="finding-description">

            ${description}

        </div>
    `;


    securityFindings.appendChild(
        finding
    );
}


// ============================================================
// SAVE SCAN HISTORY
// ============================================================

function saveScanHistory(
    scan
) {

    let history =
        JSON.parse(
            localStorage.getItem(
                "shadowScanHistory"
            )
        ) || [];


    history.unshift(
        scan
    );


    // Keep last 10 scans

    history =
        history.slice(
            0,
            10
        );


    localStorage.setItem(
        "shadowScanHistory",
        JSON.stringify(history)
    );
}


// ============================================================
// DISPLAY HISTORY
// ============================================================

function displayHistory() {

    if (!historyBody) {

        return;
    }


    let history =
        JSON.parse(
            localStorage.getItem(
                "shadowScanHistory"
            )
        ) || [];


    historyBody.innerHTML =
        "";


    if (
        history.length === 0
    ) {

        const row =
            document.createElement(
                "tr"
            );


        row.innerHTML = `
            <td colspan="5">
                No scan history yet.
            </td>
        `;


        historyBody.appendChild(
            row
        );


        return;
    }


    history.forEach(
        scan => {

            const row =
                document.createElement(
                    "tr"
                );


            row.innerHTML = `
                <td>
                    ${scan.time}
                </td>

                <td>
                    ${scan.target}
                </td>

                <td>
                    ${scan.range}
                </td>

                <td>
                    ${scan.open}
                </td>

                <td>
                    <span class="${getHistoryRiskClass(scan.risk)}">
                        ${scan.risk}
                    </span>
                </td>
            `;


            historyBody.appendChild(
                row
            );
        }
    );
}


// ============================================================
// HISTORY RISK CLASS
// ============================================================

function getHistoryRiskClass(
    risk
) {

    if (
        risk === "HIGH"
    ) {

        return "history-risk-high";
    }


    if (
        risk === "MEDIUM"
    ) {

        return "history-risk-medium";
    }


    if (
        risk === "LOW"
    ) {

        return "history-risk-low";
    }


    return "";
}


// ============================================================
// CLEAR HISTORY
// ============================================================

if (clearHistoryButton) {

    clearHistoryButton.addEventListener(
        "click",
        () => {

            localStorage.removeItem(
                "shadowScanHistory"
            );

            displayHistory();
        }
    );
}


// ============================================================
// PRESET BUTTONS
// ============================================================

const presetButtons =
    document.querySelectorAll(
        ".preset-btn"
    );


presetButtons.forEach(
    button => {

        button.addEventListener(
            "click",
            () => {

                const start =
                    button.dataset.start;

                const end =
                    button.dataset.end;


                startPortInput.value =
                    start;

                endPortInput.value =
                    end;


                output.innerHTML += `
                    <br>
                    > PRESET SELECTED: ${start}-${end}_
                `;
            }
        );
    }
);


// ============================================================
// INITIALIZE HISTORY
// ============================================================

displayHistory();


// ============================================================
// STARTUP TERMINAL MESSAGE
// ============================================================

if (output) {

    output.innerHTML = `
        > SHADOWSCAN SECURITY ENGINE INITIALIZED_<br>
        > SYSTEM STATUS: ONLINE_<br>
        > TCP SCANNER: READY_<br>
        > RISK ANALYSIS ENGINE: READY_<br>
        > WAITING FOR SCAN COMMAND...
    `;
}