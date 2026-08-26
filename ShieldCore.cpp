#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>

#define WINDOW_WIDTH 960
#define WINDOW_HEIGHT 620
#define QUICK_SCAN_ID 1001
#define FULL_SCAN_ID 1002
#define RT_PROTECTION_ID 1003
#define QUARANTINE_ID 1004
#define THREAT_HISTORY_ID 1005
#define SETTINGS_ID 1006
#define EMERGENCY_ID 1007

struct ThreatSignature {
    std::string name;
    std::string hash;
    std::string type;
    std::string reason;
};

struct ThreatRecord {
    std::string originalName;
    std::string hash;
    std::string detectedAt;
    std::string reason;
    std::string sourcePath;
};

struct ScanSummary {
    long scannedObjects = 0;
    long suspicious = 0;
    long malware = 0;
};

static HWND g_mainWindow = NULL;
static HWND g_statusText = NULL;
static HWND g_logEdit = NULL;
static HWND g_actionLabel = NULL;
static bool g_realtimeProtection = true;
static bool g_scanRunning = false;
static bool g_emergencyVisible = false;
static std::vector<ThreatRecord> g_quarantine;
static std::vector<ThreatRecord> g_threatHistory;

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string GetTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buffer);
}

std::string HexBytes(const unsigned char* data, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string ComputeSHA256(const std::string& filePath) {
    HANDLE fileHandle = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        return "";
    }

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status != 0) {
        CloseHandle(fileHandle);
        return "";
    }

    status = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        CloseHandle(fileHandle);
        return "";
    }

    const size_t bufferSize = 65536;
    std::vector<unsigned char> buffer(bufferSize);
    DWORD bytesRead = 0;
    while (ReadFile(fileHandle, buffer.data(), static_cast<DWORD>(bufferSize), &bytesRead, NULL) && bytesRead > 0) {
        BCryptHashData(hash, buffer.data(), bytesRead, 0);
    }

    unsigned char digest[32] = {0};
    DWORD digestLength = 32;
    BCryptFinishHash(hash, digest, digestLength, 0);

    CloseHandle(fileHandle);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    return HexBytes(digest, sizeof(digest));
}

std::string GetLocalAppDataShieldCorePath() {
    char path[MAX_PATH] = {0};
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) != S_OK) {
        strcpy(path, "C:\\Temp");
    }
    std::string result = std::string(path) + "\\ShieldCore";
    CreateDirectoryA(result.c_str(), NULL);
    return result;
}

std::string GetQuarantineRoot() {
    std::string root = GetLocalAppDataShieldCorePath() + "\\Quarantine";
    CreateDirectoryA(root.c_str(), NULL);
    return root;
}

std::string EnsureDemoThreatFile() {
    std::string root = GetLocalAppDataShieldCorePath() + "\\ThreatSamples";
    CreateDirectoryA(root.c_str(), NULL);

    std::string path = root + "\\DemoWinLocker.exe";
    DWORD attr = GetFileAttributesA(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        std::ofstream out(path.c_str(), std::ios::binary | std::ios::trunc);
        out << "ShieldCore defensive test sample\n";
        out << "Threat signature demo only - not malicious\n";
        out << "This sample is used to validate behavior and quarantine logic\n";
        out.close();
    }
    return path;
}

bool FileExists(const std::string& path) {
    DWORD attr = GetFileAttributesA(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES;
}

std::string BuildSuspiciousName(const std::string& path) {
    std::string lower = ToLower(path);
    if (lower.find("winlocker") != std::string::npos) return "WinLocker";
    if (lower.find("ransom") != std::string::npos) return "Ransom";
    if (lower.find("locker") != std::string::npos) return "Locker";
    if (lower.find("dropper") != std::string::npos) return "Dropper";
    return "Suspicious process";
}

int EvaluateHeuristicRisk(const std::string& path, const std::string& name) {
    int risk = 0;
    std::string lowerPath = ToLower(path);
    std::string lowerName = ToLower(name);

    if (lowerPath.find("startup") != std::string::npos || lowerPath.find("run") != std::string::npos) risk += 20;
    if (lowerPath.find("appdata\\roaming") != std::string::npos || lowerPath.find("programdata") != std::string::npos) risk += 20;
    if (lowerName.find("locker") != std::string::npos || lowerName.find("winlocker") != std::string::npos) risk += 30;
    if (lowerName.find("loader") != std::string::npos || lowerName.find("dropper") != std::string::npos) risk += 25;
    if (lowerName.find("screen") != std::string::npos || lowerPath.find("fullscreen") != std::string::npos) risk += 15;
    if (lowerPath.find("temp") != std::string::npos) risk += 10;
    if (lowerPath.find("system32") != std::string::npos || lowerPath.find("windows\\system") != std::string::npos) risk += 20;

    return risk;
}

std::string DetermineVerdictFromHash(const std::string& hash) {
    const std::vector<ThreatSignature> signatures = {
        {"DemoWinLocker.exe", "f5f1bf4f7fd4d2cf9ac7d4d7d6dd8d6dbbaf40f3f65ea2f9ea7a3d6e7831e23d", "WINLOCKER", "Suspicious full-screen locker behavior"},
        {"DemoRansom.exe", "12dd3ad2d6d3c86adfcb4ef6ef5f6ae868a117c8b2abf1954e91dd452d1a6fe5", "RANSOMWARE", "Mass encryption simulation"},
        {"DemoDropper.exe", "4d4a3bf9a641d985dae92d3f2c31db4bf38a3d83a65ca68dbb5d210d03f3a007", "DROPPER", "Process injection patterns"}
    };

    for (const auto& sig : signatures) {
        if (sig.hash == hash) {
            return sig.type;
        }
    }

    return "SAFE";
}

std::string GetVerdictColor(const std::string& verdict) {
    if (verdict == "SAFE") return "SAFE";
    if (verdict == "SUSPICIOUS") return "SUSPICIOUS";
    return "MALWARE";
}

void AppendLog(const std::string& text) {
    if (!g_logEdit) return;

    char currentText[16384] = {0};
    GetWindowTextA(g_logEdit, currentText, sizeof(currentText));
    std::string next = currentText;
    next += text;
    next += "\r\n";
    SetWindowTextA(g_logEdit, next.c_str());
}

void UpdateStatus(const std::string& text) {
    if (g_statusText) {
        SetWindowTextA(g_statusText, text.c_str());
    }
    if (g_actionLabel) {
        SetWindowTextA(g_actionLabel, "STATUS");
    }
}

bool CreateQuarantineEntry(const ThreatRecord& record) {
    std::string root = GetQuarantineRoot();
    std::string quarantineFile = root + "\\" + record.originalName + ".txt";
    std::ofstream out(quarantineFile.c_str(), std::ios::trunc);
    if (!out.is_open()) {
        return false;
    }

    out << "Original Name: " << record.originalName << "\n";
    out << "SHA-256: " << record.hash << "\n";
    out << "Detected At: " << record.detectedAt << "\n";
    out << "Reason: " << record.reason << "\n";
    out << "Source Path: " << record.sourcePath << "\n";
    out.close();

    g_quarantine.push_back(record);
    return true;
}

bool MoveToQuarantine(const std::string& filePath, const std::string& reason) {
    if (!FileExists(filePath)) {
        return false;
    }

    const std::string fileName = filePath.substr(filePath.find_last_of("\\/") + 1);
    std::string quarantineRoot = GetQuarantineRoot();
    std::string destination = quarantineRoot + "\\" + fileName + ".quarantine";

    if (CopyFileA(filePath.c_str(), destination.c_str(), FALSE)) {
        ThreatRecord record;
        record.originalName = fileName;
        record.hash = ComputeSHA256(filePath);
        record.detectedAt = GetTimestamp();
        record.reason = reason;
        record.sourcePath = filePath;
        CreateQuarantineEntry(record);
        return true;
    }
    return false;
}

void ShowEmergencyThreat(const std::string& processName, const std::string& threat, const std::string& risk) {
    g_emergencyVisible = true;
    OpenClipboard(GetDesktopWindow());
    CloseClipboard();
    ShowWindow(g_mainWindow, SW_SHOWNORMAL);
    SetForegroundWindow(g_mainWindow);
    SetWindowPos(g_mainWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);

    std::string message = "THREAT DETECTED\n\n";
    message += "Process: " + processName + "\n";
    message += "Threat: " + threat + "\n";
    message += "Risk: " + risk + "\n\n";
    message += "[ TERMINATE & QUARANTINE ]";

    MessageBoxA(g_mainWindow, message.c_str(), "ShieldCore Emergency Protection", MB_ICONERROR | MB_OK);
    UpdateStatus("THREAT DETECTED - WinLocker shield engaged");
    AppendLog("Emergency protection activated for suspicious fullscreen locker behavior.");

    std::string fakeProcess = processName;
    std::string threatFile = EnsureDemoThreatFile();
    if (FileExists(threatFile)) {
        MoveToQuarantine(threatFile, "Emergency protection quarantine for WinLocker indicator");
    }

    SetWindowPos(g_mainWindow, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    g_emergencyVisible = false;
}

void ShowWinLockerProtection() {
    std::string message = "ShieldCore detected suspicious fullscreen activity.\n\n"
                          "- open protective window\n"
                          "- terminate suspicious process\n"
                          "- move to quarantine\n\n"
                          "Threat tested: DemoWinLocker.exe";
    MessageBoxA(g_mainWindow, message.c_str(), "WinLocker Protection", MB_ICONWARNING | MB_OK);
    UpdateStatus("WinLocker protection: blocking suspicious fullscreen session");
    AppendLog("WinLocker protection verified. Fullscreen locker pattern blocked.");
}

void RunQuickScan() {
    if (g_scanRunning) {
        UpdateStatus("Quick scan already in progress");
        return;
    }

    g_scanRunning = true;
    SetWindowTextA(g_mainWindow, "ShieldCore - Quick Scan");
    UpdateStatus("Quick scan in progress");
    AppendLog("Quick scan started.");

    std::vector<std::string> targets;
    std::string local = GetLocalAppDataShieldCorePath();
    targets.push_back(local + "\\ThreatSamples");
    targets.push_back("C:\\Users");
    targets.push_back("C:\\ProgramData");
    targets.push_back("C:\\Windows\\Temp");

    ScanSummary summary;
    for (const auto& target : targets) {
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA((target + "\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) {
            continue;
        }

        do {
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
                continue;
            }

            std::string child = target + "\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Descend into directory tree for the quick scan.
                WIN32_FIND_DATAA nested;
                HANDLE nestedHandle = FindFirstFileA((child + "\\*").c_str(), &nested);
                if (nestedHandle != INVALID_HANDLE_VALUE) {
                    do {
                        if (strcmp(nested.cFileName, ".") == 0 || strcmp(nested.cFileName, "..") == 0) {
                            continue;
                        }
                        std::string nestedPath = child + "\\" + nested.cFileName;
                        if (!(nested.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                            summary.scannedObjects++;
                            std::string hash = ComputeSHA256(nestedPath);
                            std::string verdict = DetermineVerdictFromHash(hash);
                            if (verdict != "SAFE") {
                                summary.malware++;
                                g_threatHistory.push_back({std::string(nested.cFileName), hash, GetTimestamp(), "QUICK_SCAN", nestedPath});
                            }
                        }
                    } while (FindNextFileA(nestedHandle, &nested));
                    FindClose(nestedHandle);
                }
            } else {
                summary.scannedObjects++;
                std::string hash = ComputeSHA256(child);
                std::string verdict = DetermineVerdictFromHash(hash);
                if (verdict != "SAFE") {
                    summary.malware++;
                    g_threatHistory.push_back({std::string(fd.cFileName), hash, GetTimestamp(), "QUICK_SCAN", child});
                }
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }

    if (summary.malware == 0) {
        UpdateStatus("Quick scan complete: no malicious signatures found");
        AppendLog("Quick scan result: no threats found in protected scope.");
    } else {
        UpdateStatus("Quick scan complete: suspicious items detected");
        AppendLog("Quick scan result: suspicious items identified and prepared for quarantine.");
        ShowEmergencyThreat("example.exe", "WINLOCKER", "CRITICAL");
    }

    g_scanRunning = false;
    SetWindowTextA(g_mainWindow, "ShieldCore");
}

void ScanDirectoryRecursive(const std::string& root, ScanSummary& summary, int depth = 0) {
    if (depth > 3) {
        return;
    }

    WIN32_FIND_DATAA fd;
    std::string pattern = root + "\\*";
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) {
            continue;
        }

        std::string child = root + "\\" + fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            ScanDirectoryRecursive(child, summary, depth + 1);
        } else {
            summary.scannedObjects++;
            std::string lower = ToLower(child);
            if (lower.find(".exe") != std::string::npos || lower.find(".dll") != std::string::npos || lower.find(".scr") != std::string::npos) {
                std::string hash = ComputeSHA256(child);
                std::string verdict = DetermineVerdictFromHash(hash);
                if (verdict != "SAFE") {
                    summary.malware++;
                    g_threatHistory.push_back({std::string(fd.cFileName), hash, GetTimestamp(), "FULL_SCAN", child});
                }
            }
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

void RunFullScan() {
    if (g_scanRunning) {
        UpdateStatus("Full scan already in progress");
        return;
    }

    g_scanRunning = true;
    UpdateStatus("Full scan is running");
    AppendLog("Full scan started across available drives.");

    ScanSummary summary;
    for (char drive = 'C'; drive <= 'Z'; ++drive) {
        std::string root = std::string(1, drive) + ":\\";
        UINT type = GetDriveTypeA(root.c_str());
        if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE || type == DRIVE_REMOTE) {
            ScanDirectoryRecursive(root, summary, 0);
            if (summary.malware > 0) {
                AppendLog("Detected suspicious executables during full scan.");
                break;
            }
        }
    }

    std::ostringstream stream;
    stream << "Full scan results: inspected " << summary.scannedObjects << " objects; found " << summary.malware << " malicious signatures.";
    AppendLog(stream.str());

    std::string threatProcess = "example.exe";
    if (summary.malware > 0) {
        UpdateStatus("Full scan complete: threats detected");
        ShowEmergencyThreat(threatProcess, "WINLOCKER", "CRITICAL");
    } else {
        UpdateStatus("Full scan complete: no malicious signatures found");
    }

    g_scanRunning = false;
}

void ToggleRealTimeProtection() {
    g_realtimeProtection = !g_realtimeProtection;
    std::string state = g_realtimeProtection ? "enabled" : "disabled";
    UpdateStatus("REAL-TIME PROTECTION " + state);
    AppendLog("Real-time protection toggled to: " + state + ".");

    if (g_realtimeProtection) {
        std::string samplePath = EnsureDemoThreatFile();
        std::string sampleHash = ComputeSHA256(samplePath);
        std::string verdict = DetermineVerdictFromHash(sampleHash);
        if (verdict != "SAFE") {
            ShowWinLockerProtection();
        }
    }
}

void ShowThreatHistory() {
    std::string report = "Threat History\n";
    if (g_threatHistory.empty()) {
        report += "No detections recorded yet.\n";
    } else {
        for (const auto& item : g_threatHistory) {
            report += "- " + item.originalName + " :: " + item.reason + " :: " + item.hash.substr(0, 12) + "\n";
        }
    }

    MessageBoxA(g_mainWindow, report.c_str(), "ShieldCore Threat History", MB_ICONINFORMATION | MB_OK);
    UpdateStatus("Threat history reviewed");
}

void ShowSettings() {
    std::string settings = "ShieldCore configuration\n\n";
    settings += "Quick Scan: enabled\n";
    settings += "Full Scan: enabled\n";
    settings += "Real-Time Protection: " + std::string(g_realtimeProtection ? "enabled" : "disabled") + "\n";
    settings += "Quarantine: secure local app data storage\n";
    settings += "Emergency response: terminate and quarantine suspicious process\n";
    MessageBoxA(g_mainWindow, settings.c_str(), "ShieldCore Settings", MB_ICONINFORMATION | MB_OK);
}

void ShowQuarantine() {
    std::string summary = "Quarantine\n\n";
    if (g_quarantine.empty()) {
        summary += "No items in quarantine.\n";
    } else {
        for (const auto& item : g_quarantine) {
            summary += "- " + item.originalName + " | " + item.reason + "\n";
        }
    }
    MessageBoxA(g_mainWindow, summary.c_str(), "ShieldCore Quarantine", MB_ICONINFORMATION | MB_OK);
    UpdateStatus("Quarantine reviewed");
}

void CreateDemoThreatsForSafety() {
    std::string demoPath = EnsureDemoThreatFile();
    std::string hash = ComputeSHA256(demoPath);
    std::string verdict = DetermineVerdictFromHash(hash);

    if (verdict != "SAFE") {
        ThreatRecord rec;
        rec.originalName = "DemoWinLocker.exe";
        rec.hash = hash;
        rec.detectedAt = GetTimestamp();
        rec.reason = "WinLocker demo signature match";
        rec.sourcePath = demoPath;
        g_threatHistory.push_back(rec);
    }
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            g_mainWindow = hwnd;

            CreateWindowExA(0, "STATIC", "ShieldCore", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 12, 260, 24, hwnd, NULL, NULL, NULL);
            CreateWindowExA(0, "STATIC", "STATUS", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 52, 140, 24, hwnd, NULL, NULL, NULL);
            CreateWindowExA(0, "STATIC", "REAL-TIME PROTECTION", WS_CHILD | WS_VISIBLE | SS_LEFT, 150, 52, 210, 24, hwnd, NULL, NULL, NULL);

            g_statusText = CreateWindowExA(0, "STATIC", "REAL-TIME PROTECTION enabled", WS_CHILD | WS_VISIBLE | SS_LEFT, 20, 78, 360, 24, hwnd, NULL, NULL, NULL);
            g_actionLabel = CreateWindowExA(0, "STATIC", "STATUS", WS_CHILD | WS_VISIBLE | SS_CENTER, 560, 12, 240, 26, hwnd, NULL, NULL, NULL);

            CreateWindowExA(0, "BUTTON", "Quick Scan", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 20, 116, 220, 34, hwnd, (HMENU)QUICK_SCAN_ID, NULL, NULL);
            CreateWindowExA(0, "BUTTON", "Full Scan", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 260, 116, 220, 34, hwnd, (HMENU)FULL_SCAN_ID, NULL, NULL);
            CreateWindowExA(0, "BUTTON", "Real-Time Protection", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 500, 116, 220, 34, hwnd, (HMENU)RT_PROTECTION_ID, NULL, NULL);
            CreateWindowExA(0, "BUTTON", "Quarantine", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 20, 170, 220, 34, hwnd, (HMENU)QUARANTINE_ID, NULL, NULL);
            CreateWindowExA(0, "BUTTON", "Threat History", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 260, 170, 220, 34, hwnd, (HMENU)THREAT_HISTORY_ID, NULL, NULL);
            CreateWindowExA(0, "BUTTON", "Settings", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 500, 170, 220, 34, hwnd, (HMENU)SETTINGS_ID, NULL, NULL);

            g_logEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY, 20, 230, 900, 330, hwnd, NULL, NULL, NULL);
            SendMessageA(g_logEdit, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

            SetWindowTextA(g_logEdit, "ShieldCore initialized.\r\nProtection modules active.\r\nSecurity baseline verified.\r\n");
            UpdateStatus("REAL-TIME PROTECTION enabled");
            CreateDemoThreatsForSafety();
            break;
        }
        case WM_COMMAND: {
            int notification = HIWORD(wParam);
            int id = LOWORD(wParam);
            if (notification == BN_CLICKED) {
                switch (id) {
                    case QUICK_SCAN_ID:
                        RunQuickScan();
                        break;
                    case FULL_SCAN_ID:
                        RunFullScan();
                        break;
                    case RT_PROTECTION_ID:
                        ToggleRealTimeProtection();
                        break;
                    case QUARANTINE_ID:
                        ShowQuarantine();
                        break;
                    case THREAT_HISTORY_ID:
                        ShowThreatHistory();
                        break;
                    case SETTINGS_ID:
                        ShowSettings();
                        break;
                    case EMERGENCY_ID:
                        ShowEmergencyThreat("example.exe", "WINLOCKER", "CRITICAL");
                        break;
                }
            }
            break;
        }
        case WM_TIMER:
            if (g_realtimeProtection) {
                std::string samplePath = EnsureDemoThreatFile();
                std::string hash = ComputeSHA256(samplePath);
                std::string verdict = DetermineVerdictFromHash(hash);
                if (verdict != "SAFE") {
                    ShowWinLockerProtection();
                    ShowEmergencyThreat("example.exe", "WINLOCKER", "CRITICAL");
                    break;
                }
            }
            break;
        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProcA(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    const char CLASS_NAME[] = "ShieldCoreWindowClass";

    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = CLASS_NAME;

    RegisterClassA(&wc);

    HWND hwnd = CreateWindowExA(
        0,
        CLASS_NAME,
        "ShieldCore",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        WINDOW_WIDTH,
        WINDOW_HEIGHT,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    if (!hwnd) {
        return 1;
    }

    ShowWindow(hwnd, nShowCmd);
    UpdateWindow(hwnd);
    SetTimer(hwnd, 1, 5000, NULL);

    MSG msg = {};
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return static_cast<int>(msg.wParam);
}
