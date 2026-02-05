# TCP GUI Client (Python)

Ein einfacher TCP-Client mit grafischer Oberfläche (Tkinter).

## Funktionen
- Eingabe von IP und Port
- Aufbau/Trennen einer TCP-Verbindung
- Nachrichten senden
- Anzeige von gesendeten und empfangenen Daten in einem Protokollfenster

## Start
```bash
python3 tcp_gui_client.py
```

## Hinweise
- Gesendet wird UTF-8-kodierter Text.
- Empfangene Daten werden ebenfalls als UTF-8 dekodiert (`errors="replace"`).
