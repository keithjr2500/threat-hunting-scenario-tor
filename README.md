# Official Threat Hunting tor Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/keithjr2500/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “keithjr2500” downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the reaction of a file calle “tor-shopping-list.txt” on the desktop at 2025-06-14T03:14:39.9631145Z. These events began at: 2025-06-14T03:01:01.0899181Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "ryantthreateven"
| where InitiatingProcessAccountName == "keithjr2500"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-06-14T03:01:01.0899181Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName == InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/8018adbd-bfc1-496f-99b5-991294f2889a)>


---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvents table for ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.0.1.exe”at  from their Downloads folder, using a command that triggered a silent installation. 2025-06-14T03:05:36.3826104Z, an employee on the “ryantthreateven” device ran the file tor-browser-windows-x86_64-portable-14.0.1.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "ryantthreateven"
| where ProcessCommandLine startswith "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
<![image](https://github.com/user-attachments/assets/18302a5d-8844-4815-8dfd-9023d3f8a69e)>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “employee” actually opened the tor browser. There was evidence that they did open it at 2025-06-14T03:05:59.2235767Z. There were several other instances of firefox.exe (Tor) as well as tor.exe spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "ryantthreateven"
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/8a86ba1a-7f3f-4e9a-9f84-5cad0afdb541)>


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-06-14T03:06:09.4990173Z, the device named ryantthreateven successfully established a network connection using the application tor.exe, located in the Tor Browser directory on the user's desktop. The connection was made to the IP address 193.31.27.127 over port 9001, which is commonly associated with the Tor network, and was linked to the URL https://www.5fhtge7pr2kyk3r.com. This activity indicates that the Tor Browser was actively used on the device at that time.There were a few other connections. There were a few other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "ryantthreateven"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "9151", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/68f8a0ec-a707-4aac-97a1-dfabc7a08dfd)>


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-06-14T03:01:01.0899181Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\keithjr2500\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-06-14T03:05:36.3826104Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.3.exe /S`
- **File Path:** `C:\Users\keithjr2500\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-06-14T03:05:59.2235767Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\keithjr2500\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-06-14T03:06:09.4990173Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\keithjr2500\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-06-14T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2025-06-14T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-06-14T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\keithjr2500\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

---

## Summary

On June 14, 2025, a full Tor Browser session was initiated by the user keithjr2500 on the machine ryantthreateven. The Tor installer was downloaded, renamed, and executed within minutes, leading to the deployment of browser and launcher files to the user’s Desktop. Shortly after, network connections to known Tor relays over ports 9001, 9150, and 80 were successfully established by both tor.exe and the bundled firefox.exe, confirming active Tor usage. Subsequent file activity, including the creation of tor-shopping-list.txt and related browser data, suggests the user engaged in browsing and local data storage. The session concluded with the renaming of the shopping list file, potentially as an effort to conceal its contents or purpose.


---

## Response Taken

TOR usage was confirmed on endpoint ryantthreateven by the user keithjr2500. The device was isolated and the user's direct manager was notified.


---# threat-hunting-scenario-tor
