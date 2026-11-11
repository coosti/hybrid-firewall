# Hybrid Multilayer Firewall

Hybrid Multilayer Firewall is a network traffic analysis prototype that combines packet-level and flow-level analysis to classify packets as **ALLOW** or **DROP**.

The two analysis levels are:

- **Packet analysis:** examines individual packet information, including IP addresses, protocols, ports, and header consistency.
- **Flow analysis:** tracks bidirectional flows and collects aggregate characteristics, including packet counts, transferred bytes, duration, and communication rates.

Analysis runs **locally and offline** on previously captured network traffic stored in PCAP or PCAPNG files. ALLOW/DROP decisions classify the captured traffic; they do not block packets on a live network.

The **Policy Engine** applies configurable rules to packet information, flow statistics, and events within time windows to produce an ALLOW/DROP decision and the findings that explain it.

## Usage

### Installation

Clone the repository and open the project directory:

```bash
git clone https://github.com/coosti/hybrid-firewall.git
cd hybrid-firewall
```

### Environment setup

The project has been tested with Python 3.13. Run the following commands from the project root.

Create a Python virtual environment:

```bash
python -m venv venv
```

Activate it on macOS/Linux:

```bash
source venv/bin/activate
```

On Windows, using PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

### Running the analysis

Run the main script with the capture file to analyze:

```bash
python src/main.py data/policy_test_pcaps/01_tcp_handshake_ok.pcap --profile test --json result.json
```

This example requires the sample capture to be present locally. The `data/` directory is excluded from Git by default.

Replace the capture path with the PCAP or PCAPNG file you want to analyze. The `--profile` option selects a policy profile (`demo`, `custom`, or `test`); the default is `demo`. The `test` profile is configured for the scenarios in `data/policy_test_pcaps/`.

Results are displayed in the terminal. The optional `--json` argument also saves a report to the specified file.

Policy profiles, including allowed networks and services and detection thresholds, can be configured in `src/firewall/engine/policy_profile.py`.
