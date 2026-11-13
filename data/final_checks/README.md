# Suite finale: 21 catture

Profilo: `test2`. Risultati verificati il 13 novembre 2026: 2.527 pacchetti,
349 ALLOW e 2.178 DROP.

I nomi originali sono conservati: 01-16 e 18-22. Non esiste un file 17.
La tabella della relazione numera invece gli scenari consecutivamente 1-21:
gli ID 17, 18, 19, 20 e 21 corrispondono ai file 18, 19, 20, 21 e 22.
La corrispondenza completa si trova in `risultati.csv`.

`manifest.csv` descrive gli scenari e gli esiti attesi con il profilo test2.
`risultati.csv` riporta i conteggi osservati, le regole principali di DROP,
tutti i findings (anche informativi) e gli hash SHA-256 delle catture.

Il file `20_tcp_handshake_wrong_order.pcap` contiene SYN, SYN+ACK e ACK
tutti nella direzione dell'iniziatore: verifica la direzione errata del
SYN+ACK. Produce TCP_STATE_ANOMALY e TCP_HANDSHAKE_INCOMPLETE informativi,
con tre ALLOW. Il nome storico del file rimane invariato.

Nei casi ad alto packet rate possono comparire sia FLOW_PACKET_RATE sia
FLOW_PEAK_PACKET_RATE; FLOW_PACKET_RATE e' la regola principale di DROP.
I findings sull'handshake non sono regole bloccanti.

Esempio dalla radice del progetto:

```bash
python src/main.py data/final_checks_tcp_validazione/20_tcp_handshake_wrong_order.pcap --profile test2 --json esito.json
```
