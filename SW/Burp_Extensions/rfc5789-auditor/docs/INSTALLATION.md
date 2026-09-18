# Installation Guide

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Burp Suite | Community or Professional 2023.1+ | Must support the Montoya API |
| JDK | 17+ | Only required for building from source |
| Gradle | 8+ | Only required for building from source (wrapper included) |

## Option A: Install Pre-built JAR

1. Download `rfc5789-auditor-1.0.0.jar` from the [Releases](https://github.com/rfc5789-auditor/rfc5789-auditor/releases) page.
2. Skip to [Loading in Burp Suite](#loading-in-burp-suite).

## Option B: Build from Source

### 1. Clone the repository

```bash
git clone https://github.com/rfc5789-auditor/rfc5789-auditor.git
cd rfc5789-auditor
```

### 2. Verify JDK 17

```bash
java -version
# Expected: openjdk version "17.x.x" or later
```

If JDK 17 is not installed, install it via your package manager:

```bash
# macOS (Homebrew)
brew install openjdk@17

# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# Windows (winget)
winget install EclipseAdoptium.Temurin.17.JDK
```

### 3. Build the fat JAR

```bash
./gradlew fatJar
```

On Windows:

```bash
gradlew.bat fatJar
```

The JAR is produced at:

```
build/libs/rfc5789-auditor-1.0.0.jar
```

### 4. Run tests (optional)

```bash
./gradlew test
```

## Loading in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions** -> **Installed**.
3. Click **Add**.
4. In the dialog:
   - **Extension type**: Java
   - **Extension file**: Browse to `rfc5789-auditor-1.0.0.jar`
5. Click **Next**.

## Verifying Installation

### Extensions Tab

After loading, you should see **RFC 5789 Auditor** listed in the Installed extensions table with a status of "Loaded".

### Output Tab

Click on the extension entry and check the **Output** tab. A successful load displays:

```
[RFC5789] Passive scan check registered.
[RFC5789] Active scan check registered.
[RFC5789] Context menu provider registered.
[RFC5789] Traffic monitor registered (always-on PATCH detection).
[RFC5789] UI tab group registered.

============================================================
  RFC 5789 Auditor v1.0.0
  by RFC 5789 Auditor Contributors
============================================================
  PATCH Method Security & Compliance Scanner
------------------------------------------------------------
  Passive checks : Enabled (detects missing headers,
                   generic Content-Types, missing Accept-Patch)
  Active checks  : Enabled (Burp Pro) / Context menu (Community)
  Default mode   : SAFE (canary payloads only)
------------------------------------------------------------
  Right-click any PATCH request -> 'Run RFC 5789 Audit'
============================================================
```

### Errors Tab

The **Errors** tab should be empty. If you see `java.lang.UnsupportedClassVersionError`, you need to configure Burp to use JDK 17+ (see troubleshooting below).

## Troubleshooting

### `UnsupportedClassVersionError` or `class file version 61.0`

Burp Suite is running on a JRE older than 17. Solutions:

- **Burp 2023.1+** ships with a bundled JRE that supports Java 17. Make sure you are running a current version of Burp.
- If using a custom JRE, set the `JAVA_HOME` environment variable to a JDK 17+ installation before launching Burp.

### Extension loads but context menu item does not appear

The context menu item **Run RFC 5789 Audit** only appears when you right-click on a request that uses the `PATCH` HTTP method. Verify that:

1. You have a PATCH request selected in Proxy History, Repeater, or the Target site map.
2. You are right-clicking on the request itself, not on the response.

### Extension loads but active scan does not run checks

Active scan integration requires **Burp Suite Professional**. In Community edition, use the context menu instead:

1. Send a PATCH request through the Proxy or use Repeater.
2. Right-click the request -> **Run RFC 5789 Audit**.

### No findings generated against the test harness

1. Verify the test harness is running: `curl http://localhost:5789/api/health`
2. Ensure Burp is configured to proxy traffic to `localhost:5789`.
3. Check that the extension mode is set to **SAFE** (default). Safe mode uses canary payloads that the test harness is designed to detect.

### Build fails with `Could not resolve net.portswigger.burp.extensions:montoya-api`

The Montoya API dependency is hosted on Maven Central. Ensure you have internet access and that your Gradle configuration does not restrict repository access. If behind a corporate proxy, configure Gradle's proxy settings in `~/.gradle/gradle.properties`:

```properties
systemProp.http.proxyHost=proxy.example.com
systemProp.http.proxyPort=8080
systemProp.https.proxyHost=proxy.example.com
systemProp.https.proxyPort=8080
```

### Extension causes Burp to hang or become unresponsive

The Atomicity Race Condition check (AMB-03) sends concurrent PATCH requests (default: 10). If the target server is slow, this can consume HTTP connections. Reduce the concurrency setting in the Configuration tab, or disable AMB-03 if testing against a single-threaded server.
