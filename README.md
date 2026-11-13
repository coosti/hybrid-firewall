# Hybrid Multilayer Firewall

Hybrid Multilayer Firewall is a network traffic analysis prototype that combines packet-level and flow-level analysis to classify packets as **ALLOW** or **DROP**.

The two analysis levels are:

- **Packet analysis:** examines individual packet information, including IP addresses, protocols, ports, and header consistency.
- **Flow analysis:** tracks bidirectional flows and collects aggregate characteristics, including packet counts, transferred bytes, duration, and communication rates.

Analysis runs **locally and offline** on previously captured network traffic stored in PCAP or PCAPNG files, classifying the captured traffic.

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
python src/main.py data/final_checks_tcp_validazione/01_rate_basso.pcap --profile test2 --json result.json
```

This example requires the sample capture to be present locally. The `data/` directory is excluded from Git by default.

Replace the capture path with the PCAP or PCAPNG file you want to analyze. The default profile is `demo`. Use `--profile custom` for the example custom profile.

- Use `--profile test2` for the IPv4/IPv6 scenarios in `data/final_checks_tcp_validazione/` in the 21-capture suite. The corrective pytest cases supply their own thresholds to isolate individual rate rules.
- Use `--profile test1` for the service, scan, flood, and volume scenarios in `data/policy_test_pcaps/`.

The legacy CLI names `test-policy` and `test` are aliases for `test1` and `test2`, respectively.

Results are displayed in the terminal. The optional `--json` argument also saves a report to the specified file.

Policy profiles, including allowed networks and services and detection thresholds, can be configured in `src/firewall/engine/policy_profile.py`.

The JSON report includes the mean and peak packet rates for each flow under `flow_packet_rates`.
The peak counts packets in both directions over a one-second sliding window, open at the start and closed at the end.
Set `FlowLimits.max_peak_packets_per_second` to enable `FLOW_PEAK_PACKET_RATE`.
The rule blocks packets of the flow when its observed peak exceeds the configured limit.
The `test2` profile sets this limit to 150 packets/s. Other bundled profiles expose the measure in JSON and leave the rule disabled.

## Capture suites and verification

The `data/` directory contains only the two suites described in the report and the original Wireshark captures:

- `data/policy_test_pcaps/`: 17 captures, profile `test1`; 322 packets, 169 ALLOW, 153 DROP. Case `17_udp_large_volume.pcap` belongs to this suite.
- `data/final_checks_tcp_validazione/`: 21 captures, profile `test2`; 2,527 packets, 349 ALLOW, 2,178 DROP. Filenames run from 01 to 22 with no file 17. The report table numbers the scenarios consecutively from 1 to 21; `risultati.csv` maps those IDs to filenames.
- `data/samples/`: the original `sample_capture.pcapng` and `short_capture.pcapng`, preserved byte for byte. The manifest records packet counts and SHA-256 hashes. The `demo` profile is an example policy, so its ALLOW/DROP results do not establish whether domestic traffic is safe.

Each synthetic suite includes `risultati.csv` with observed counts, findings and capture hashes. The final suite also includes `manifest.csv` with scenario descriptions and expected behavior. Handshake findings are informative and do not independently cause DROP.

Run the reproducible verification from the project root:

```bash
python scripts/verifica_suite.py
```

This verifies all 38 synthetic captures against the report and writes fresh JSON reports under `reports/consegna_20261113/`. It also analyzes both original Wireshark captures. When the delivery copy in `../Mancini/data/samples/` is available, the script verifies that its samples match the originals.

Generators are in `scripts/`. Regenerate the two synthetic suites with:

```bash
python scripts/generate_policy_pcaps.py
python scripts/genera_test_finali_handshake.py
```

The Python regression tests and their private corrective fixtures are outside `data/`, under `tests/`. In PowerShell:

```powershell
$env:PYTHONPATH = 'src'
python -B -m pytest tests -q -p no:cacheprovider
```
