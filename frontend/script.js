// ============================================
// SHADOWSCAN - FRONTEND SCRIPT
// Version 4.2 - Backend Matched
// ============================================

const API_BASE = "http://127.0.0.1:8000";

// Largest range one scan may cover (matches the FULL SCAN preset).
const MAX_PORT_RANGE = 65535;

// ============================================
// GLOBAL STATE
// ============================================

let currentScanId = null;
let currentResults = [];
let lastScanData = null;
let scanTimer = null;
let isScanning = false;


// ============================================
// DOM ELEMENTS
// ============================================

const targetInput = document.getElementById("target");
const startPortInput = document.getElementById("startPort");
const endPortInput = document.getElementById("endPort");

const scanButton = document.getElementById("scanButton");
const stopButton = document.getElementById("stopButton");

const progressText = document.getElementById("progressText");
const progressFill = document.getElementById("progressFill");

const portsScanned = document.getElementById("portsScanned");
const openPorts = document.getElementById("openPorts");
const closedPorts = document.getElementById("closedPorts");
const averageRisk = document.getElementById("averageRisk");
const highRisk = document.getElementById("highRisk");
const criticalRisk = document.getElementById("criticalRisk");

const riskLevel = document.getElementById("riskLevel");

const lowRiskCount = document.getElementById("lowRiskCount");
const mediumRiskCount = document.getElementById("mediumRiskCount");
const highRiskCount = document.getElementById("highRiskCount");
const criticalRiskCount = document.getElementById("criticalRiskCount");

const lowRiskBar = document.getElementById("lowRiskBar");
const mediumRiskBar = document.getElementById("mediumRiskBar");
const highRiskBar = document.getElementById("highRiskBar");
const criticalRiskBar = document.getElementById("criticalRiskBar");

const clearHistoryButton = document.getElementById("clearHistory");
const historyBody = document.getElementById("historyBody");

const exportReportButton = document.getElementById("exportReport");

const resultSearch = document.getElementById("resultSearch");
const riskFilter = document.getElementById("riskFilter");
const resultsBody = document.getElementById("resultsBody");

const securityFindings = document.getElementById("securityFindings");

const output = document.getElementById("output");


// ============================================
// INITIALIZATION
// ============================================

document.addEventListener("DOMContentLoaded", () => {

    console.log("================================");
    console.log("ShadowScan frontend initialized");
    console.log("================================");

    loadHistory();
    checkBackend();
    resetScanUI();
    setScanningState(false);

    if (scanButton) {
        scanButton.addEventListener(
            "click",
            startScan
        );
    }

    if (stopButton) {
        stopButton.addEventListener(
            "click",
            stopScan
        );
    }

    document
        .querySelectorAll(".preset-btn")
        .forEach(button => {

            button.addEventListener(
                "click",
                () => setPreset(
                    button.dataset.start,
                    button.dataset.end
                )
            );
        });

    if (resultSearch) {
        resultSearch.addEventListener(
            "input",
            renderResults
        );
    }

    if (riskFilter) {
        riskFilter.addEventListener(
            "change",
            renderResults
        );
    }

    if (clearHistoryButton) {
        clearHistoryButton.addEventListener(
            "click",
            clearHistory
        );
    }

    if (exportReportButton) {
        exportReportButton.addEventListener(
            "click",
            exportReport
        );
    }
});


// ============================================
// CHECK BACKEND
// ============================================

async function checkBackend() {

    try {

        const response = await fetch(
            `${API_BASE}/`
        );

        if (!response.ok) {
            throw new Error(
                `Backend returned ${response.status}`
            );
        }

        const data =
            await response.json();

        console.log(
            "Backend connected:",
            data
        );

        addTerminalMessage(
            "Backend connection established.",
            "success"
        );

    } catch (error) {

        console.error(
            "Backend connection failed:",
            error
        );

        addTerminalMessage(
            "BACKEND CONNECTION FAILED",
            "error"
        );
    }
}


// ============================================
// RESET UI
// ============================================

function resetScanUI() {

    currentScanId = null;
    currentResults = [];
    lastScanData = null;

    if (progressText) {
        progressText.textContent = "0% — WAITING";
    }

    if (progressFill) {
        progressFill.style.width = "0%";
    }

    if (portsScanned) {
        portsScanned.textContent = "0";
    }

    if (openPorts) {
        openPorts.textContent = "0";
    }

    if (closedPorts) {
        closedPorts.textContent = "0";
    }

    if (averageRisk) {
        averageRisk.textContent = "0";
    }

    if (highRisk) {
        highRisk.textContent = "0";
    }

    if (criticalRisk) {
        criticalRisk.textContent = "0";
    }

    if (riskLevel) {
        riskLevel.textContent = "—";
    }

    resetRiskDistribution();

    if (resultsBody) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="6">
                    No scan results yet.
                </td>
            </tr>
        `;
    }

    if (securityFindings) {

        securityFindings.innerHTML = `
            <div class="finding-empty">
                No security findings yet.
            </div>
        `;
    }

    if (exportReportButton) {
        exportReportButton.disabled = true;
    }
}


// ============================================
// RESET RISK DISTRIBUTION
// ============================================

function resetRiskDistribution() {

    if (lowRiskCount) {
        lowRiskCount.textContent = "0";
    }

    if (mediumRiskCount) {
        mediumRiskCount.textContent = "0";
    }

    if (highRiskCount) {
        highRiskCount.textContent = "0";
    }

    if (criticalRiskCount) {
        criticalRiskCount.textContent = "0";
    }

    if (lowRiskBar) {
        lowRiskBar.style.width = "0%";
    }

    if (mediumRiskBar) {
        mediumRiskBar.style.width = "0%";
    }

    if (highRiskBar) {
        highRiskBar.style.width = "0%";
    }

    if (criticalRiskBar) {
        criticalRiskBar.style.width = "0%";
    }
}


// ============================================
// SCANNING STATE
// ============================================

function setScanningState(scanning) {

    isScanning = scanning;

    if (scanButton) {
        scanButton.disabled = scanning;
    }

    if (stopButton) {
        stopButton.disabled = !scanning;
        stopButton.style.display = scanning ? "" : "none";
    }

    document
        .querySelectorAll(".preset-btn")
        .forEach(button => {
            button.disabled = scanning;
        });

    if (targetInput) {
        targetInput.disabled = scanning;
    }

    if (startPortInput) {
        startPortInput.disabled = scanning;
    }

    if (endPortInput) {
        endPortInput.disabled = scanning;
    }
}


// ============================================
// START SCAN
// ============================================

async function startScan() {

    if (isScanning) {
        return;
    }

    const target =
        targetInput?.value.trim();

    const startPort =
        parseInt(
            startPortInput?.value,
            10
        );

    const endPort =
        parseInt(
            endPortInput?.value,
            10
        );


    // ----------------------------------------
    // VALIDATION
    // ----------------------------------------

    if (!target) {

        alert(
            "Please enter a target."
        );

        return;
    }

    if (
        Number.isNaN(startPort) ||
        Number.isNaN(endPort)
    ) {

        alert(
            "Please enter valid port numbers."
        );

        return;
    }

    if (
        startPort < 1 ||
        endPort > 65535 ||
        startPort > endPort
    ) {

        alert(
            "Port range must be between 1 and 65535."
        );

        return;
    }

    if (
        endPort - startPort + 1 > MAX_PORT_RANGE
    ) {

        alert(
            `Maximum scan range is ${MAX_PORT_RANGE} ports.`
        );

        return;
    }


    // ----------------------------------------
    // PREPARE UI
    // ----------------------------------------

    clearScanTimer();

    resetScanUI();

    setScanningState(true);

    addTerminalMessage(
        `Starting scan: ${target}:${startPort}-${endPort}`,
        "info"
    );


    try {

        // ------------------------------------
        // START BACKEND SCAN
        // ------------------------------------

        const response =
            await fetch(
                `${API_BASE}/scan?target=${encodeURIComponent(
                    target
                )}&start_port=${startPort}&end_port=${endPort}`,
                {
                    method: "POST"
                }
            );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Scan start failed (${response.status}): ${errorText}`
            );
        }


        const data =
            await response.json();

        console.log(
            "SCAN START RESPONSE:",
            data
        );


        if (data.error) {

            throw new Error(
                data.error
            );
        }


        currentScanId =
            data.scan_id;


        if (!currentScanId) {

            throw new Error(
                "Backend did not return a scan_id."
            );
        }


        addTerminalMessage(
            `Scan started. ID: ${currentScanId}`,
            "success"
        );


        // ------------------------------------
        // START POLLING
        // ------------------------------------

        pollScanStatus();


    } catch (error) {

        console.error(
            "START SCAN ERROR:",
            error
        );

        addTerminalMessage(
            `SCAN ERROR: ${error.message}`,
            "error"
        );

        setScanningState(false);
    }
}


// ============================================
// POLL STATUS
// ============================================

async function pollScanStatus() {

    if (!currentScanId) {
        return;
    }


    try {

        const response =
            await fetch(
                `${API_BASE}/scan/${currentScanId}/status`
            );


        if (!response.ok) {

            throw new Error(
                `Status request failed: ${response.status}`
            );
        }


        const data =
            await response.json();


        console.log(
            "SCAN STATUS:",
            data
        );


        updateProgress(data);


        // ------------------------------------
        // COMPLETED
        // ------------------------------------

        if (
            data.status === "completed"
        ) {

            clearScanTimer();

            updateProgress({
                ...data,
                progress: 100
            });


            addTerminalMessage(
                "SCAN COMPLETED",
                "success"
            );


            await loadScanResults();


            setScanningState(false);

            return;
        }


        // ------------------------------------
        // CANCELLED
        // ------------------------------------

        if (
            data.status === "cancelled"
        ) {

            clearScanTimer();

            addTerminalMessage(
                "SCAN CANCELLED",
                "warning"
            );

            setScanningState(false);

            return;
        }


        // ------------------------------------
        // ERROR
        // ------------------------------------

        if (
            data.status === "failed" ||
            data.status === "error"
        ) {

            clearScanTimer();

            addTerminalMessage(
                data.error
                    ? `SCAN FAILED: ${data.error}`
                    : "SCAN FAILED",
                "error"
            );

            setScanningState(false);

            return;
        }


        // ------------------------------------
        // CONTINUE
        // ------------------------------------

        scanTimer =
            setTimeout(
                pollScanStatus,
                500
            );


    } catch (error) {

        console.error(
            "POLL ERROR:",
            error
        );

        clearScanTimer();

        addTerminalMessage(
            `STATUS ERROR: ${error.message}`,
            "error"
        );

        setScanningState(false);
    }
}


// ============================================
// UPDATE PROGRESS
// ============================================

function updateProgress(data) {

    const progress =
        Number(
            data.progress || 0
        );


    const totalPorts =
        Number(
            data.total_ports ||
            (
                Number(data.end_port || 0) -
                Number(data.start_port || 0) +
                1
            )
        );


    const scanned =
        Number(
            data.ports_scanned ??
            Math.round(
                totalPorts *
                progress /
                100
            )
        );


    if (progressText) {

        const labels = {
            starting: "STARTING",
            scanning: "SCANNING",
            cancelling: "CANCELLING",
            cancelled: "CANCELLED",
            completed: "COMPLETE",
            failed: "FAILED"
        };

        const label =
            labels[data.status];

        progressText.textContent =
            label
                ? `${progress}% — ${label}`
                : `${progress}%`;
    }


    if (progressFill) {

        progressFill.style.width =
            `${progress}%`;
    }


    if (portsScanned) {

        portsScanned.textContent =
            scanned;
    }


    // The status endpoint sends the running open-port count as
    // "open_ports"; the final result uses "open_ports_count".

    const liveOpen =
        data.open_ports_count ??
        (
            typeof data.open_ports === "number"
                ? data.open_ports
                : undefined
        );


    if (liveOpen !== undefined) {

        if (openPorts) {

            openPorts.textContent =
                liveOpen;
        }
    }


    const liveClosed =
        data.closed_ports ??
        (
            liveOpen !== undefined
                ? Math.max(scanned - liveOpen, 0)
                : undefined
        );


    if (liveClosed !== undefined) {

        if (closedPorts) {

            closedPorts.textContent =
                liveClosed;
        }
    }
}


// ============================================
// LOAD FINAL RESULT
// ============================================

async function loadScanResults() {

    if (!currentScanId) {
        return;
    }


    try {

        /*
         * IMPORTANT:
         *
         * Actual backend endpoint:
         *
         * GET /scan/{scan_id}/result
         *
         * NOT /results
         */

        const response =
            await fetch(
                `${API_BASE}/scan/${currentScanId}/result`
            );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Result request failed (${response.status}): ${errorText}`
            );
        }


        const data =
            await response.json();


        console.log(
            "===================================="
        );

        console.log(
            "FINAL SHADOWSCAN RESULT"
        );

        console.log(
            data
        );

        console.log(
            "===================================="
        );


        // ------------------------------------
        // SAVE COMPLETE RESULT
        // ------------------------------------

        lastScanData =
            data;


        /*
         * ACTUAL BACKEND FIELD:
         *
         * open_ports
         *
         * There is NO data.results.
         */

        currentResults =
            Array.isArray(
                data.open_ports
            )
                ? data.open_ports
                : [];


        console.log(
            "OPEN PORT RESULTS:",
            currentResults
        );


        // ------------------------------------
        // UPDATE UI
        // ------------------------------------

        updateStats(data);

        renderResults();

        updateSecurityFindings(data);

        saveScanToHistory(data);


        // ------------------------------------
        // ENABLE EXPORT
        // ------------------------------------

        if (exportReportButton) {

            exportReportButton.disabled =
                false;
        }


        addTerminalMessage(
            "Scan results loaded successfully.",
            "success"
        );


    } catch (error) {

        console.error(
            "LOAD RESULTS ERROR:",
            error
        );

        addTerminalMessage(
            `RESULT ERROR: ${error.message}`,
            "error"
        );
    }
}


// ============================================
// UPDATE STATISTICS
// ============================================

function updateStats(data) {

    // ----------------------------------------
    // ACTUAL BACKEND FIELDS
    // ----------------------------------------

    const scanned =
        Number(
            data.ports_scanned || 0
        );


    const opened =
        Number(
            data.open_ports_count || 0
        );


    const closed =
        Number(
            data.closed_ports || 0
        );


    const avg =
        Number(
            data.average_risk_score || 0
        );


    const overallRisk =
        String(
            data.overall_risk ||
            calculateOverallRisk(avg)
        ).toUpperCase();


    // ----------------------------------------
    // BASIC STATS
    // ----------------------------------------

    if (portsScanned) {

        portsScanned.textContent =
            scanned;
    }


    if (openPorts) {

        openPorts.textContent =
            opened;
    }


    if (closedPorts) {

        closedPorts.textContent =
            closed;
    }


    if (averageRisk) {

        averageRisk.textContent =
            avg.toFixed(0);
    }


    // ----------------------------------------
    // HIGH / CRITICAL
    // ----------------------------------------

    const high =
        countRisk(
            "HIGH"
        );


    const critical =
        countRisk(
            "CRITICAL"
        );


    if (highRisk) {

        highRisk.textContent =
            high;
    }


    if (criticalRisk) {

        criticalRisk.textContent =
            critical;
    }


    // ----------------------------------------
    // OVERALL RISK
    // ----------------------------------------

    if (riskLevel) {

        riskLevel.textContent =
            overallRisk || "—";
    }


    // ----------------------------------------
    // RISK DISTRIBUTION
    // ----------------------------------------

    updateRiskDistribution(
        data
    );
}


// ============================================
// OVERALL RISK CALCULATION
// ============================================

function calculateOverallRisk(
    score
) {

    score =
        Number(score || 0);


    if (score >= 80) {
        return "CRITICAL";
    }


    if (score >= 60) {
        return "HIGH";
    }


    if (score >= 30) {
        return "MEDIUM";
    }


    return "LOW";
}


// ============================================
// RISK DISTRIBUTION
// ============================================

function updateRiskDistribution(
    data
) {

    const counts = {

        LOW: 0,

        MEDIUM: 0,

        HIGH: 0,

        CRITICAL: 0
    };


    // ----------------------------------------
    // ACTUAL BACKEND risk_counts
    // ----------------------------------------

    if (
        data.risk_counts &&
        typeof data.risk_counts === "object"
    ) {

        counts.LOW =
            Number(
                data.risk_counts.LOW || 0
            );


        counts.MEDIUM =
            Number(
                data.risk_counts.MEDIUM || 0
            );


        counts.HIGH =
            Number(
                data.risk_counts.HIGH || 0
            );


        counts.CRITICAL =
            Number(
                data.risk_counts.CRITICAL || 0
            );
    }


    // ----------------------------------------
    // UPDATE NUMBERS
    // ----------------------------------------

    if (lowRiskCount) {

        lowRiskCount.textContent =
            counts.LOW;
    }


    if (mediumRiskCount) {

        mediumRiskCount.textContent =
            counts.MEDIUM;
    }


    if (highRiskCount) {

        highRiskCount.textContent =
            counts.HIGH;
    }


    if (criticalRiskCount) {

        criticalRiskCount.textContent =
            counts.CRITICAL;
    }


    // ----------------------------------------
    // TOTAL
    // ----------------------------------------

    const total =
        counts.LOW +
        counts.MEDIUM +
        counts.HIGH +
        counts.CRITICAL;


    if (total === 0) {

        if (lowRiskBar) {
            lowRiskBar.style.width = "0%";
        }

        if (mediumRiskBar) {
            mediumRiskBar.style.width = "0%";
        }

        if (highRiskBar) {
            highRiskBar.style.width = "0%";
        }

        if (criticalRiskBar) {
            criticalRiskBar.style.width = "0%";
        }

        return;
    }


    // ----------------------------------------
    // UPDATE BARS
    // ----------------------------------------

    if (lowRiskBar) {

        lowRiskBar.style.width =
            `${(
                counts.LOW /
                total
            ) * 100}%`;
    }


    if (mediumRiskBar) {

        mediumRiskBar.style.width =
            `${(
                counts.MEDIUM /
                total
            ) * 100}%`;
    }


    if (highRiskBar) {

        highRiskBar.style.width =
            `${(
                counts.HIGH /
                total
            ) * 100}%`;
    }


    if (criticalRiskBar) {

        criticalRiskBar.style.width =
            `${(
                counts.CRITICAL /
                total
            ) * 100}%`;
    }
}


// ============================================
// COUNT RISK
// ============================================

function countRisk(
    level
) {

    const wanted =
        String(
            level
        ).toUpperCase();


    return currentResults.filter(
        result =>
            String(
                result.risk || ""
            ).toUpperCase() === wanted
    ).length;
}


// ============================================
// RENDER RESULTS
// ============================================

function renderResults() {

    if (!resultsBody) {
        return;
    }


    const search =
        resultSearch?.value
            ?.trim()
            .toLowerCase() || "";


    const selectedRisk =
        riskFilter?.value
            ?.trim()
            .toUpperCase() || "ALL";


    let filtered =
        [...currentResults];


    // ----------------------------------------
    // SEARCH
    // ----------------------------------------

    if (search) {

        filtered =
            filtered.filter(
                result => {

                    const searchableText = [

                        result.port,

                        result.service,

                        result.banner,

                        result.risk,

                        result.risk_reason,

                        result.finding,

                        result.recommendation

                    ]
                        .join(" ")
                        .toLowerCase();


                    return searchableText
                        .includes(search);
                }
            );
    }


    // ----------------------------------------
    // RISK FILTER
    // ----------------------------------------

    if (
        selectedRisk &&
        selectedRisk !== "ALL"
    ) {

        filtered =
            filtered.filter(
                result =>
                    String(
                        result.risk || ""
                    ).toUpperCase() ===
                    selectedRisk
            );
    }


    // ----------------------------------------
    // EMPTY
    // ----------------------------------------

    if (
        filtered.length === 0
    ) {

        resultsBody.innerHTML = `
            <tr>
                <td colspan="6">
                    No open ports found.
                </td>
            </tr>
        `;

        return;
    }


    // ----------------------------------------
    // TABLE
    // ----------------------------------------

    resultsBody.innerHTML =
        filtered.map(
            result => {

                const risk =
                    String(
                        result.risk ||
                        "UNKNOWN"
                    ).toUpperCase();


                const riskClass =
                    risk.toLowerCase();


                const port =
                    escapeHTML(
                        result.port ??
                        "—"
                    );


                const service =
                    escapeHTML(
                        result.service ||
                        "Unknown"
                    );


                const banner =
                    escapeHTML(
                        result.banner ||
                        "—"
                    );


                const score =
                    result.risk_score ??
                    "—";


                const reason =
                    escapeHTML(
                        result.risk_reason ||
                        "—"
                    );


                return `
                    <tr>

                        <td>
                            ${port}
                        </td>

                        <td>
                            ${service}
                        </td>

                        <td>
                            <span
                                class="risk-badge ${riskClass}"
                            >
                                ${risk}
                            </span>
                        </td>

                        <td>
                            ${score}
                        </td>

                        <td>
                            ${banner}
                        </td>

                        <td>
                            ${reason}
                        </td>

                    </tr>
                `;
            }
        ).join("");
}


// ============================================
// SECURITY FINDINGS
// ============================================

function updateSecurityFindings(
    data
) {

    if (!securityFindings) {
        return;
    }


    const findings =
        Array.isArray(
            data.security_findings
        )
            ? data.security_findings
            : [];


    if (
        findings.length === 0
    ) {

        securityFindings.innerHTML = `
            <div class="finding-empty">
                No security findings detected.
            </div>
        `;

        return;
    }


    securityFindings.innerHTML =
        findings.map(
            finding => {

                const severity =
                    String(
                        finding.severity ||
                        "LOW"
                    ).toUpperCase();


                const severityClass =
                    severity.toLowerCase();


                const title =
                    escapeHTML(
                        finding.title ||
                        "Security Finding"
                    );


                const port =
                    escapeHTML(
                        finding.port ??
                        "—"
                    );


                const service =
                    escapeHTML(
                        finding.service ||
                        "Unknown"
                    );


                const score =
                    finding.risk_score ??
                    "—";


                const description =
                    escapeHTML(
                        finding.description ||
                        "No description available."
                    );


                const recommendation =
                    escapeHTML(
                        finding.recommendation ||
                        "Review this service."
                    );


                return `
                    <div
                        class="finding"
                        data-severity="${severity}"
                    >

                        <strong>
                            ${title}
                        </strong>

                        <div>

                            <b>Port:</b>
                            ${port}

                            &nbsp;&nbsp;

                            <b>Service:</b>
                            ${service}

                            &nbsp;&nbsp;

                            <b>Risk Score:</b>
                            ${score}

                        </div>

                        <span
                            class="finding-severity ${severityClass}"
                        >
                            ${severity}
                        </span>

                        <p>

                            <b>Description:</b>

                            ${description}

                        </p>

                        <div
                            class="finding-recommendation"
                        >

                            <strong>
                                Recommendation:
                            </strong>

                            ${recommendation}

                        </div>

                    </div>
                `;
            }
        ).join("");
}


// ============================================
// STOP SCAN
// ============================================

async function stopScan() {

    if (!currentScanId) {
        return;
    }


    try {

        const response =
            await fetch(
                `${API_BASE}/scan/${currentScanId}/cancel`,
                {
                    method: "POST"
                }
            );


        if (!response.ok) {

            const errorText =
                await response.text();

            throw new Error(
                `Cancel failed (${response.status}): ${errorText}`
            );
        }


        const data =
            await response.json();


        console.log(
            "CANCEL RESPONSE:",
            data
        );


        addTerminalMessage(
            "Cancellation requested...",
            "warning"
        );


    } catch (error) {

        console.error(
            "STOP SCAN ERROR:",
            error
        );


        addTerminalMessage(
            `STOP ERROR: ${error.message}`,
            "error"
        );
    }
}


// ============================================
// CLEAR TIMER
// ============================================

function clearScanTimer() {

    if (scanTimer) {

        clearTimeout(
            scanTimer
        );

        scanTimer = null;
    }
}


// ============================================
// SAVE HISTORY
// ============================================

function saveScanToHistory(
    data
) {

    try {

        const history =
            JSON.parse(
                localStorage.getItem(
                    "shadowScanHistory"
                ) || "[]"
            );


        const historyItem = {

            id:
                data.scan_id ||
                Date.now(),

            target:
                data.target ||
                "Unknown",

            start_port:
                data.start_port ??
                "",

            end_port:
                data.end_port ??
                "",

            total_ports:
                data.ports_scanned ??
                0,

            open_ports:
                data.open_ports_count ??
                0,

            average_risk_score:
                data.average_risk_score ??
                0,

            risk_level:
                data.overall_risk ||
                calculateOverallRisk(
                    data.average_risk_score
                ),

            timestamp:
                new Date().toISOString()
        };


        history.unshift(
            historyItem
        );


        localStorage.setItem(
            "shadowScanHistory",
            JSON.stringify(
                history.slice(
                    0,
                    20
                )
            )
        );


        loadHistory();


    } catch (error) {

        console.error(
            "HISTORY SAVE ERROR:",
            error
        );
    }
}


// ============================================
// LOAD HISTORY
// ============================================

function loadHistory() {

    if (!historyBody) {
        return;
    }


    try {

        const history =
            JSON.parse(
                localStorage.getItem(
                    "shadowScanHistory"
                ) || "[]"
            );


        if (
            !Array.isArray(history) ||
            history.length === 0
        ) {

            historyBody.innerHTML = `
                <tr>
                    <td
                        colspan="7"
                    >
                        No scan history yet.
                    </td>
                </tr>
            `;

            return;
        }


        historyBody.innerHTML =
            history.map(
                item => {

                    const date =
                        new Date(
                            item.timestamp
                        );


                    const risk =
                        String(
                            item.risk_level ||
                            "LOW"
                        ).toUpperCase();


                    const riskClass =
                        risk.toLowerCase();


                    return `
                        <tr>

                            <td>
                                ${escapeHTML(
                                    item.target ||
                                    "Unknown"
                                )}
                            </td>

                            <td>
                                ${
                                    item.start_port
                                }
                                -
                                ${
                                    item.end_port
                                }
                            </td>

                            <td>
                                ${
                                    item.total_ports
                                }
                            </td>

                            <td>
                                ${
                                    item.open_ports
                                }
                            </td>

                            <td>
                                ${
                                    Number(
                                        item.average_risk_score ||
                                        0
                                    ).toFixed(0)
                                }
                            </td>

                            <td>
                                <span
                                    class="risk-badge ${riskClass}"
                                >
                                    ${risk}
                                </span>
                            </td>

                            <td>
                                ${
                                    date.toLocaleString()
                                }
                            </td>

                        </tr>
                    `;
                }
            ).join("");


    } catch (error) {

        console.error(
            "HISTORY LOAD ERROR:",
            error
        );
    }
}


// ============================================
// CLEAR HISTORY
// ============================================

function clearHistory() {

    if (
        !confirm(
            "Clear all ShadowScan history?"
        )
    ) {
        return;
    }


    localStorage.removeItem(
        "shadowScanHistory"
    );


    loadHistory();


    addTerminalMessage(
        "Scan history cleared.",
        "info"
    );
}


// ============================================
// EXPORT REPORT
// ============================================

function exportReport() {

    if (!lastScanData) {

        alert(
            "No scan results available to export."
        );

        return;
    }


    const data =
        lastScanData;


    const lines = [];


    // ----------------------------------------
    // HEADER
    // ----------------------------------------

    lines.push(
        "============================================================"
    );

    lines.push(
        "                       SHADOWSCAN"
    );

    lines.push(
        "                 SECURITY SCAN REPORT"
    );

    lines.push(
        "============================================================"
    );

    lines.push("");


    // ----------------------------------------
    // INFORMATION
    // ----------------------------------------

    lines.push(
        "SCAN INFORMATION"
    );

    lines.push(
        "------------------------------------------------------------"
    );

    lines.push(
        `Target: ${data.target || "Unknown"}`
    );

    lines.push(
        `Resolved Target: ${
            data.resolved_target ||
            "Unknown"
        }`
    );

    lines.push(
        `Port Range: ${
            data.start_port
        } - ${
            data.end_port
        }`
    );

    lines.push(
        `Ports Scanned: ${
            data.ports_scanned ||
            0
        }`
    );

    lines.push(
        `Open Ports: ${
            data.open_ports_count ||
            0
        }`
    );

    lines.push(
        `Closed Ports: ${
            data.closed_ports ||
            0
        }`
    );

    lines.push(
        `Average Risk Score: ${
            data.average_risk_score ||
            0
        }`
    );

    lines.push(
        `Overall Risk: ${
            data.overall_risk ||
            "LOW"
        }`
    );

    lines.push(
        `Scan Status: ${
            data.scan_status ||
            "completed"
        }`
    );

    lines.push("");


    // ----------------------------------------
    // RISK DISTRIBUTION
    // ----------------------------------------

    const counts =
        getRiskCounts(data);


    lines.push(
        "RISK DISTRIBUTION"
    );

    lines.push(
        "------------------------------------------------------------"
    );

    lines.push(
        `LOW: ${counts.LOW}`
    );

    lines.push(
        `MEDIUM: ${counts.MEDIUM}`
    );

    lines.push(
        `HIGH: ${counts.HIGH}`
    );

    lines.push(
        `CRITICAL: ${counts.CRITICAL}`
    );

    lines.push("");


    // ----------------------------------------
    // OPEN PORTS
    // ----------------------------------------

    lines.push(
        "OPEN PORTS"
    );

    lines.push(
        "------------------------------------------------------------"
    );


    if (
        currentResults.length === 0
    ) {

        lines.push(
            "No open ports detected."
        );

    } else {

        currentResults.forEach(
            result => {

                lines.push(
                    `Port: ${
                        result.port ??
                        "—"
                    }`
                );

                lines.push(
                    `Service: ${
                        result.service ||
                        "Unknown"
                    }`
                );

                lines.push(
                    `Risk: ${
                        result.risk ||
                        "UNKNOWN"
                    }`
                );

                lines.push(
                    `Risk Score: ${
                        result.risk_score ??
                        "—"
                    }`
                );

                lines.push(
                    `Banner: ${
                        result.banner ||
                        "—"
                    }`
                );

                lines.push(
                    `Reason: ${
                        result.risk_reason ||
                        "—"
                    }`
                );

                lines.push(
                    `Finding: ${
                        result.finding ||
                        "—"
                    }`
                );

                lines.push(
                    `Recommendation: ${
                        result.recommendation ||
                        "—"
                    }`
                );

                lines.push(
                    "------------------------------------------------------------"
                );
            }
        );
    }


    lines.push("");


    // ----------------------------------------
    // SECURITY FINDINGS
    // ----------------------------------------

    lines.push(
        "SECURITY FINDINGS"
    );

    lines.push(
        "------------------------------------------------------------"
    );


    const findings =
        Array.isArray(
            data.security_findings
        )
            ? data.security_findings
            : [];


    if (
        findings.length === 0
    ) {

        lines.push(
            "No security findings detected."
        );

    } else {

        findings.forEach(
            (finding, index) => {

                lines.push(
                    `${index + 1}. ${
                        finding.title ||
                        "Security Finding"
                    }`
                );

                lines.push(
                    `Severity: ${
                        finding.severity ||
                        "LOW"
                    }`
                );

                lines.push(
                    `Port: ${
                        finding.port ??
                        "—"
                    }`
                );

                lines.push(
                    `Service: ${
                        finding.service ||
                        "Unknown"
                    }`
                );

                lines.push(
                    `Risk Score: ${
                        finding.risk_score ??
                        "—"
                    }`
                );

                lines.push(
                    `Description: ${
                        finding.description ||
                        "—"
                    }`
                );

                lines.push(
                    `Recommendation: ${
                        finding.recommendation ||
                        "—"
                    }`
                );

                lines.push("");
            }
        );
    }


    // ----------------------------------------
    // FOOTER
    // ----------------------------------------

    lines.push(
        "============================================================"
    );

    lines.push(
        "Generated by ShadowScan"
    );

    lines.push(
        "Authorized security testing only."
    );

    lines.push(
        "============================================================"
    );


    // ----------------------------------------
    // DOWNLOAD
    // ----------------------------------------

    const blob =
        new Blob(
            [
                lines.join("\n")
            ],
            {
                type:
                    "text/plain;charset=utf-8"
            }
        );


    const url =
        URL.createObjectURL(
            blob
        );


    const link =
        document.createElement(
            "a"
        );


    const safeTarget =
        String(
            data.target ||
            "target"
        )
            .replace(
                /[^a-zA-Z0-9.-]/g,
                "_"
            );


    link.href =
        url;


    link.download =
        `ShadowScan_Report_${safeTarget}.txt`;


    document.body.appendChild(
        link
    );


    link.click();


    document.body.removeChild(
        link
    );


    URL.revokeObjectURL(
        url
    );


    addTerminalMessage(
        "Security report exported successfully.",
        "success"
    );
}


// ============================================
// GET RISK COUNTS
// ============================================

function getRiskCounts(
    data
) {

    const counts = {

        LOW: 0,

        MEDIUM: 0,

        HIGH: 0,

        CRITICAL: 0
    };


    if (
        data.risk_counts &&
        typeof data.risk_counts === "object"
    ) {

        counts.LOW =
            Number(
                data.risk_counts.LOW || 0
            );

        counts.MEDIUM =
            Number(
                data.risk_counts.MEDIUM || 0
            );

        counts.HIGH =
            Number(
                data.risk_counts.HIGH || 0
            );

        counts.CRITICAL =
            Number(
                data.risk_counts.CRITICAL || 0
            );
    }


    return counts;
}


// ============================================
// TERMINAL MESSAGE
// ============================================

function addTerminalMessage(
    message,
    type = "info"
) {

    if (!output) {
        return;
    }


    const line =
        document.createElement(
            "div"
        );


    line.className =
        `terminal-line ${type}`;


    const time =
        new Date()
            .toLocaleTimeString();


    line.textContent =
        `[${time}] ${message}`;


    output.appendChild(
        line
    );


    output.scrollTop =
        output.scrollHeight;
}


// ============================================
// ESCAPE HTML
// ============================================

function escapeHTML(
    value
) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );
}


// ============================================
// PRESETS
// ============================================

function setPreset(
    start,
    end
) {

    if (startPortInput) {

        startPortInput.value =
            start;
    }


    if (endPortInput) {

        endPortInput.value =
            end;
    }
}


// ============================================
// GLOBAL FUNCTIONS
// ============================================

window.startScan =
    startScan;

window.stopScan =
    stopScan;

window.clearHistory =
    clearHistory;

window.exportReport =
    exportReport;

window.setPreset =
    setPreset;