//
//  NodiGuardShield.swift
//  NodiGuard Active RASP (Runtime Application Self-Protection) Wall for iOS.
//  Protects against IPA decompilation, Frida dynamic hooks, LLDB debugging, and Jailbreak tampering.
//

import Foundation
import UIKit
import Darwin

public final class NodiGuardShield {
    public static let shared = NodiGuardShield()
    
    // HONEYPOT TRAP: Decompiled strings will reveal this decoy token.
    // If an attacker attempts to query the API with this honey-token, their IP is immediately banned on Cloudflare WAF.
    public let canaryHoneyToken = "paintrace_canary_honey_trap_ios_9981aef0"
    
    private init() {}
    
    /// Initializes and arms all anti-reverse engineering sensors.
    public func armWall(gatewayURL: String = "https://ai.iotservices.my") {
        #if !DEBUG
        checkJailbreak(gatewayURL: gatewayURL)
        detectDebugger(gatewayURL: gatewayURL)
        detectFridaHook(gatewayURL: gatewayURL)
        preventDebuggerAttachment()
        #endif
    }
    
    /// 1. Detects Jailbreak environment (Cydia, Sileo, Substrate, sandbox escape)
    private func checkJailbreak(gatewayURL: String) {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/lib/apt"
        ]
        for path in suspiciousPaths {
            if FileManager.default.fileExists(atPath: path) {
                triggerTamperDefense(reason: "Jailbreak Binary Detected at \(path)", gatewayURL: gatewayURL)
                return
            }
        }
        
        // Sandbox write test
        let testPath = "/private/nodiguard_jailbreak_test.txt"
        do {
            try "tamper_test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: testPath)
            triggerTamperDefense(reason: "Sandbox Integrity Violated (Root Write Permitted)", gatewayURL: gatewayURL)
        } catch {
            // Normal sandboxed behavior
        }
    }
    
    /// 2. Detects LLDB / GDB debugger attachment via sysctl
    private func detectDebugger(gatewayURL: String) {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let junk = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        if junk == 0 && (info.kp_proc.p_flag & P_TRACED) != 0 {
            triggerTamperDefense(reason: "Active Debugger Attached (P_TRACED Flag Set)", gatewayURL: gatewayURL)
        }
    }
    
    /// 3. Detects Frida Dynamic Instrumentation Server & Dylibs
    private func detectFridaHook(gatewayURL: String) {
        // Check for Frida default listening port 27042
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(27042).bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        if sock >= 0 {
            let res = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            close(sock)
            if res == 0 {
                triggerTamperDefense(reason: "Frida Server Port 27042 Open (Active Hooking)", gatewayURL: gatewayURL)
                return
            }
        }
    }
    
    /// 4. Disables ptrace attachment at kernel level
    private func preventDebuggerAttachment() {
        let ptracePtr = dlsym(dlopen(nil, RTLD_NOW), "ptrace")
        if let ptracePtr = ptracePtr {
            typealias PtraceType = @convention(c) (CInt, pid_t, CInt, CInt) -> CInt
            let ptraceFunc = unsafeBitCast(ptracePtr, to: PtraceType.self)
            _ = ptraceFunc(31, 0, 0, 0) // PT_DENY_ATTACH = 31
        }
    }
    
    /// 5. Self-Defense Reaction: Dispatches telemetry beacon and self-destructs
    private func triggerTamperDefense(reason: String, gatewayURL: String) {
        // Dispatches telemetry beacon to trigger automated Cloudflare IP Ban
        guard let url = URL(string: "\(gatewayURL)/api/security/tamper-alert") else {
            exit(0)
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let payload: [String: Any] = [
            "platform": "iOS",
            "reason": reason,
            "device": UIDevice.current.model,
            "timestamp": ISO8601DateFormatter().string(from: Date())
        ]
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        
        let task = URLSession.shared.dataTask(with: request) { _, _, _ in
            // Exit immediately after sending threat beacon
            exit(0)
        }
        task.resume()
        
        // Block main thread to prevent further execution
        Thread.sleep(forTimeInterval: 0.5)
        exit(0)
    }
}
