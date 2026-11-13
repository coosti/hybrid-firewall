# Suite policy: 17 catture

Profilo: `test1`. Risultati verificati il 13 novembre 2026: 322 pacchetti,
169 ALLOW e 153 DROP.

I file sono numerati 01-17. `17_udp_large_volume.pcap` appartiene a questa
suite ed e' necessario per il controllo FLOW_BYTE_COUNT della relazione.
L'assenza del file 17 riguarda soltanto la suite finale da 21 catture.

`risultati.csv` contiene ID della relazione, nomi dei file, conteggi osservati,
regole principali di DROP, findings e hash SHA-256 delle catture.

Esempio dalla radice del progetto:

```bash
python src/main.py data/policy_test_pcaps/17_udp_large_volume.pcap --profile test1 --json esito.json
```
