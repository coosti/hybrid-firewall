# Osservazione dell'handshake TCP

Il `FlowAnalyzer` ricostruisce la sequenza SYN → SYN+ACK opposto → ACK
dell'iniziatore, indipendentemente dall'ordine canonico degli endpoint.
`FlowAnalysis` espone `tcp_state`, `tcp_initiator`, `tcp_state_anomalies`,
`handshake_observed` e `tcp_reset_observed`. Il controllo usa flag e direzione:
non verifica numeri di sequenza o acknowledgement e non ricostruisce TCP completo.

Le ritrasmissioni SYN/SYN+ACK mantengono il progresso. Catture senza SYN iniziale,
flag mancanti durante l'handshake e simultaneous open restano `UNKNOWN`.
Un RST porta a `UNKNOWN` e interrompe il tracciamento per quella istanza di
flusso, conservando l'eventuale `handshake_observed`; FIN resta una caratteristica
osservata. Dopo un RST non vengono ricostruiti ulteriori tentativi sulla stessa
istanza: timeout o fine cattura ne determinano la finalizzazione.

Il `PolicyEngine` aggiunge segnalazioni informative `TCP_HANDSHAKE_INCOMPLETE`
per tentativi osservati ancora incompleti e `TCP_STATE_ANOMALY` per SYN+ACK nella
direzione dell'iniziatore. Queste segnalazioni non causano DROP. Gli stati non
ricostruibili espongono i controlli come non valutati; le altre regole della
policy continuano a determinare la decisione.
