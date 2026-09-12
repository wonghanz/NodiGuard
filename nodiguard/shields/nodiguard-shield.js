/**
 * NodiGuard Active Web Cyber Wall (nodiguard-shield.js)
 * Protects SPA/Web applications against DevTools debugging, code tampering, and reverse engineering.
 */

(function () {
    'use strict';

    // HONEYPOT TRAP: Scraped JS bundles will expose this decoy token.
    // If an attacker sends any request with this token, Cloudflare WAF bans their IP immediately.
    const CANARY_HONEY_TOKEN = "paintrace_canary_honey_trap_web_d558ab01";

    const GATEWAY_URL = window.NODIGUARD_GATEWAY_URL || "https://ai.iotservices.my";

    function reportThreat(reason) {
        try {
            navigator.sendBeacon(
                `${GATEWAY_URL}/api/security/tamper-alert`,
                JSON.stringify({
                    platform: "Web",
                    reason: reason,
                    userAgent: navigator.userAgent,
                    timestamp: new Date().toISOString()
                })
            );
        } catch (e) {}

        // Corrupt in-memory session tokens and freeze page
        sessionStorage.clear();
        localStorage.clear();
        document.body.innerHTML = `
            <div style="background:#0b0f19;color:#ff4d4f;height:100vh;display:flex;align-items:center;justify-content:center;font-family:sans-serif;text-align:center;">
                <div>
                    <h2>[SECURITY VIOLATION DETECTED]</h2>
                    <p>Tampering or unauthorized debugging detected. Your session and IP have been quarantined.</p>
                </div>
            </div>
        `;
        throw new Error("Security Violation: Execution Aborted.");
    }

    // 1. DevTools Detection via Timing Trap
    let devtoolsOpen = false;
    const threshold = 160;

    setInterval(function () {
        const start = performance.now();
        // Trigger potential debugger pause
        (function () {}.constructor("debugger")());
        const end = performance.now();
        if (end - start > threshold) {
            if (!devtoolsOpen) {
                devtoolsOpen = true;
                reportThreat("Developer Tools / Debugger Attached (Execution Paused)");
            }
        }
    }, 1000);

    // 2. Window Dimension Heuristic (F12 Docked Inspection)
    window.addEventListener("resize", function () {
        const widthThreshold = window.outerWidth - window.innerWidth > 160;
        const heightThreshold = window.outerHeight - window.innerHeight > 160;
        if (widthThreshold || heightThreshold) {
            reportThreat("Developer Console Docked / Inspected");
        }
    });

    // Expose clean interface to application
    window.NodiGuardShield = {
        armed: true,
        version: "0.1.0",
        getHoneyToken: () => CANARY_HONEY_TOKEN
    };
})();
