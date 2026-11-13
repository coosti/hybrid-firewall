# Catture originali Wireshark

Le due catture PCAPNG sono conservate byte per byte, senza rigenerazione,
filtraggio, anonimizzazione o modifica dei timestamp.

- `sample_capture.pcapng`: 14.131 pacchetti, 304 flussi.
- `short_capture.pcapng`: 16.724 pacchetti, 150 flussi.

Il controllo del 13 novembre 2026 ha confermato che gli hash SHA-256
corrispondono a quelli dei samples gia' presenti nella cartella Mancini.
Gli hash completi sono in `manifest.csv`.

I conteggi non qualificano il traffico come sicuro o malevolo. Per analizzare
traffico domestico occorre scegliere una policy adatta alle reti e ai servizi
osservati: il profilo `demo` contiene autorizzazioni dimostrative.
