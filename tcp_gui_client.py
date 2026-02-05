import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText


class TcpGuiClient:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("TCP Client")
        self.root.geometry("820x560")

        self.sock: socket.socket | None = None
        self.connected = False
        self.receiver_thread: threading.Thread | None = None

        self.ip_var = tk.StringVar(value="127.0.0.1")
        self.port_var = tk.StringVar(value="5000")
        self.status_var = tk.StringVar(value="Nicht verbunden")

        self._build_ui()
        # Non-printable prefix added before sending messages.       

    def _build_ui(self) -> None:
        connection_frame = ttk.LabelFrame(self.root, text="Verbindung")
        connection_frame.pack(fill="x", padx=12, pady=(12, 8))

        ttk.Label(connection_frame, text="IP:").grid(row=0, column=0, padx=6, pady=8, sticky="w")
        ip_entry = ttk.Entry(connection_frame, textvariable=self.ip_var, width=20)
        ip_entry.grid(row=0, column=1, padx=6, pady=8, sticky="w")

        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, padx=6, pady=8, sticky="w")
        port_entry = ttk.Entry(connection_frame, textvariable=self.port_var, width=10)
        port_entry.grid(row=0, column=3, padx=6, pady=8, sticky="w")

        self.connect_btn = ttk.Button(connection_frame, text="Verbinden", command=self.connect)
        self.connect_btn.grid(row=0, column=4, padx=6, pady=8)

        self.disconnect_btn = ttk.Button(connection_frame, text="Trennen", command=self.disconnect, state="disabled")
        self.disconnect_btn.grid(row=0, column=5, padx=6, pady=8)

        ttk.Label(connection_frame, textvariable=self.status_var).grid(row=0, column=6, padx=8, pady=8, sticky="w")

        logs_frame = ttk.LabelFrame(self.root, text="Sende-/Empfangsprotokoll")
        logs_frame.pack(fill="both", expand=True, padx=12, pady=8)

        self.log_text = ScrolledText(logs_frame, wrap="word", state="disabled")
        self.log_text.tag_config("sent", foreground="#1b8f3a")
        self.log_text.tag_config("recv", foreground="#1f5fbf")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)

        send_frame = ttk.LabelFrame(self.root, text="Nachricht senden")
        send_frame.pack(fill="x", padx=12, pady=(0, 12))

        self.message_entry = ScrolledText(send_frame, height=5, wrap="word")
        self.message_entry.pack(fill="x", padx=8, pady=(8, 4))

        controls = ttk.Frame(send_frame)
        controls.pack(fill="x", padx=8, pady=(0, 8))

        self.send_btn = ttk.Button(controls, text="Senden", command=self.send_message, state="disabled")
        self.send_btn.pack(side="left")

        ttk.Button(controls, text="Eingabe leeren", command=self.clear_input).pack(side="left", padx=6)
        ttk.Button(controls, text="Protokoll leeren", command=self.clear_log).pack(side="left")

    def connect(self) -> None:
        if self.connected:
            return

        ip = self.ip_var.get().strip()
        port_str = self.port_var.get().strip()

        if not ip:
            messagebox.showerror("Fehler", "Bitte eine IP-Adresse eingeben.")
            return

        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            messagebox.showerror("Fehler", "Bitte einen gültigen Port zwischen 1 und 65535 eingeben.")
            return

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((ip, port))
        except OSError as exc:
            sock.close()
            messagebox.showerror("Verbindungsfehler", f"Verbindung fehlgeschlagen:\n{exc}")
            return

        sock.settimeout(None)
        self.sock = sock
        self.connected = True

        self.connect_btn.config(state="disabled")
        self.disconnect_btn.config(state="normal")
        self.send_btn.config(state="normal")
        self.status_var.set(f"Verbunden mit {ip}:{port}")
        self._append_log("SYSTEM", f"Verbunden mit {ip}:{port}")

        self.receiver_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receiver_thread.start()

    def disconnect(self) -> None:
        if not self.connected:
            return

        self.connected = False
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

        self.connect_btn.config(state="normal")
        self.disconnect_btn.config(state="disabled")
        self.send_btn.config(state="disabled")
        self.status_var.set("Nicht verbunden")
        self._append_log("SYSTEM", "Verbindung getrennt")

    def send_message(self) -> None:
        if not self.connected or self.sock is None:
            messagebox.showwarning("Nicht verbunden", "Bitte zuerst verbinden.")
            return

        message = self.message_entry.get("1.0", "end").rstrip("\n")
        message = message.replace("\r\n", "\n")
        if not message:
            return

        try:
            payload = self._prepare_payload(message)
            self.sock.sendall(payload)
            self._append_log("GESENDET", message)
            self.message_entry.delete("1.0", "end")
        except OSError as exc:
            self._append_log("SYSTEM", f"Senden fehlgeschlagen: {exc}")
            self.disconnect()

    def _receive_loop(self) -> None:
        while self.connected and self.sock is not None:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                decoded = data.decode("utf-8", errors="replace")
                self.root.after(0, self._append_log, "EMPFANGEN", decoded)
            except OSError:
                break

        self.root.after(0, self._handle_remote_close)

    def _handle_remote_close(self) -> None:
        if self.connected:
            self._append_log("SYSTEM", "Verbindung wurde vom Gegenüber geschlossen")
            self.disconnect()

    def _append_log(self, tag: str, message: str) -> None:
        tag_key = self._tag_key_for_log(tag)
        self.log_text.config(state="normal")
        for line in message.splitlines() or [""]:
            if tag_key:
                self.log_text.insert("end", f"[{tag}] {line}\n", tag_key)
            else:
                self.log_text.insert("end", f"[{tag}] {line}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _tag_key_for_log(self, tag: str) -> str:
        if tag == "GESENDET":
            return "sent"
        if tag == "EMPFANGEN":
            return "recv"
        return ""

    def _format_prefix_for_log(self, data: bytes) -> str:
        if not data:
            return ""
        hex_parts = " ".join(f"0x{b:02X}" for b in data)
        return f"<{hex_parts}> "

    def _prepare_payload(self, message: str) -> bytes:
        """Adjust outgoing packet so the literal '</REHM>' delimiter is not present."""
        adjusted_message = message.replace("</REHM>", "</REHM\x00>")
        return adjusted_message.encode("utf-8")

    def clear_input(self) -> None:
        self.message_entry.delete("1.0", "end")

    def clear_log(self) -> None:
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def on_close(self) -> None:
        self.disconnect()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = TcpGuiClient(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
