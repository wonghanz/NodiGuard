package com.nodiguard.shield

import android.content.Context
import android.content.pm.PackageManager
import android.os.Debug
import android.os.Process
import java.io.BufferedReader
import java.io.File
import java.io.FileReader
import java.net.HttpURLConnection
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import kotlin.concurrent.thread

/**
 * NodiGuard Active RASP (Runtime Application Self-Protection) Wall for Android.
 * Neutralizes APK decompilation, Smali tampering, Frida dynamic hooks, and Magisk root injection.
 */
object NodiGuardShield {

    // HONEYPOT TRAP: Decompiled strings in Jadx/Apktool will expose this honey-token.
    // If an attacker sends any request with this token, Cloudflare WAF bans their IP permanently.
    const val CANARY_HONEY_TOKEN = "paintrace_canary_honey_trap_android_c729ab"

    fun armWall(context: Context, gatewayUrl: String = "https://ai.iotservices.my", expectedCertSha256: String? = null) {
        thread(isDaemon = true) {
            detectRoot(context, gatewayUrl)
            detectFrida(gatewayUrl)
            detectDebugger(gatewayUrl)
            detectProxy(gatewayUrl)
            if (expectedCertSha256 != null) {
                verifyApkSignature(context, expectedCertSha256, gatewayUrl)
            }
        }
    }

    /** 1. Detects Root & Magisk binaries */
    private fun detectRoot(context: Context, gatewayUrl: String) {
        val rootPaths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        for (path in rootPaths) {
            if (File(path).exists()) {
                triggerTamperDefense("Root Binary Found at $path", gatewayUrl)
                return
            }
        }
    }

    /** 2. Detects Frida Dynamic Hook Server & frida-agent.so in memory */
    private fun detectFrida(gatewayUrl: String) {
        // A. Check for Frida default listening port 27042
        try {
            Socket("127.0.0.1", 27042).use {
                triggerTamperDefense("Frida Hook Server Port 27042 Active", gatewayUrl)
                return
            }
        } catch (_: Exception) {}

        // B. Inspect /proc/self/maps for injected frida-agent or xposed libraries
        try {
            val reader = BufferedReader(FileReader("/proc/self/maps"))
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                if (line!!.contains("frida-agent") || line!!.contains("gadget.so") || line!!.contains("xposed")) {
                    reader.close()
                    triggerTamperDefense("Injected Hook Library Found in Memory: $line", gatewayUrl)
                    return
                }
            }
            reader.close()
        } catch (_: Exception) {}
    }

    /** 3. Detects ADB / Android Studio Debugger */
    private fun detectDebugger(gatewayUrl: String) {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
            triggerTamperDefense("Active Debugger Connected to Android Process", gatewayUrl)
        }
    }

    /** 4. Detects Charles / Fiddler MITM Proxy */
    private fun detectProxy(gatewayUrl: String) {
        val proxyHost = System.getProperty("http.proxyHost")
        val proxyPort = System.getProperty("http.proxyPort")
        if (!proxyHost.isNullOrEmpty() && !proxyPort.isNullOrEmpty()) {
            triggerTamperDefense("MITM Proxy Detected ($proxyHost:$proxyPort)", gatewayUrl)
        }
    }

    /** 5. Verifies APK signature hash against tampering & re-signing */
    private fun verifyApkSignature(context: Context, expectedSha256: String, gatewayUrl: String) {
        try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            for (sig in packageInfo.signatures) {
                val md = MessageDigest.getInstance("SHA-256")
                val digest = md.digest(sig.toByteArray())
                val hashHex = digest.joinToString("") { "%02x".format(it) }
                if (!hashHex.equals(expectedSha256, ignoreCase = true)) {
                    triggerTamperDefense("APK Signature Mismatch! Repackaging Detected.", gatewayUrl)
                    return
                }
            }
        } catch (_: Exception) {}
    }

    /** 6. Reaction: Dispatches telemetry beacon to NodiGuard / Cloudflare, then terminates process */
    private fun triggerTamperDefense(reason: String, gatewayUrl: String) {
        thread {
            try {
                val url = URL("$gatewayUrl/api/security/tamper-alert")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true
                conn.connectTimeout = 3000
                conn.readTimeout = 3000

                val payload = """
                    {"platform": "Android", "reason": "$reason"}
                """.trimIndent()

                conn.outputStream.use { it.write(payload.toByteArray()) }
                conn.responseCode
            } catch (_: Exception) {}

            // Immediately kill process
            Process.killProcess(Process.myPid())
            System.exit(0)
        }
    }
}
