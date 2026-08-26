# ShieldCore

ShieldCore is a defensive-security antivirus prototype built for Windows demonstration use. It focuses on identifying suspicious executable behavior, risky startup paths, and WinLocker-style blocking activity without performing any harmful actions. The project is intended for safe research, training, and defensive security demonstrations.

## Purpose

ShieldCore is designed to show how a Windows security product can:

- perform quick and full scans of common system locations;
- evaluate files by SHA-256 signature checks;
- apply risk scoring to suspicious file and process behavior;
- monitor executable creation and modification activity;
- block suspicious full-screen locker behavior;
- move suspicious items into local quarantine storage;
- present a compact security dashboard for defensive use.

The program is not a destructive or offensive tool. It does not disable Windows Defender, delete system files, encrypt user data, or establish a remote command channel.

## Supported Windows versions

ShieldCore is intended for Windows 10 and Windows 11 systems, including standard desktop environments. It is a defensive demonstration application and depends on typical Win32 APIs available in modern Windows builds.

## Included protection features

- Quick Scan for common startup and temporary locations
- Full Scan across available local drives
- SHA-256 signature matching against local test threat samples
- Heuristic risk scoring with suspicious indicator weighting
- Real-Time Protection for executable and process monitoring
- WinLocker behavior blocking and emergency response flow
- Local quarantine storage with metadata logging
- Threat history and configuration display

## Safety and limits

This software is a defensive-security demonstration and should be used only in controlled environments. It is not intended to replace a commercial endpoint security solution, and its malware database is intentionally limited to safe test samples used for demonstration purposes.

## How to run

1. Copy ShieldCore.exe to a Windows system.
2. Double-click ShieldCore.exe.
3. Use the controls in the main interface to run Quick Scan, Full Scan, and other protection modules.

The program is a standalone Windows PE executable and does not require Python, a virtual environment, or any installer.

## Project status

ShieldCore is a defensive-security project created for demonstration, training, and evaluation. It is designed to show protective behavior only and does not contain any harmful payloads, persistence, spyware, or unauthorized remote communication.
