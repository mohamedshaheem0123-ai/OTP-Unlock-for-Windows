import tkinter as tk
from tkinter import messagebox
import json
import os
import urllib.parse
import urllib.request
import urllib.error


GATE_URL = os.getenv("OTP_GATE_URL", "http://127.0.0.1:8001/local-gate")


class OTPGate:
    def __init__(self, root):
        self.root = root

        self.root.title("OTP Authentication")
        self.root.attributes("-fullscreen", True)
        self.root.attributes("-topmost", True)
        self.root.protocol("WM_DELETE_WINDOW", self.block_close)
        self.root.configure(bg="#111827")

        frame = tk.Frame(
            root,
            bg="#1f2937",
            padx=50,
            pady=40
        )
        frame.place(
            relx=0.5,
            rely=0.5,
            anchor="center"
        )

        title = tk.Label(
            frame,
            text="OTP Authentication Required",
            font=("Segoe UI", 28, "bold"),
            fg="white",
            bg="#1f2937"
        )
        title.pack(pady=(0, 15))

        message = tk.Label(
            frame,
            text="Enter your username, password and OTP.",
            font=("Segoe UI", 14),
            fg="#d1d5db",
            bg="#1f2937"
        )
        message.pack(pady=(0, 25))

        # Username
        username_label = tk.Label(
            frame,
            text="Username",
            font=("Segoe UI", 12),
            fg="white",
            bg="#1f2937"
        )
        username_label.pack(anchor="w")

        self.username_entry = tk.Entry(
            frame,
            font=("Segoe UI", 18),
            width=25
        )
        self.username_entry.pack(pady=(5, 15))

        # Password
        password_label = tk.Label(
            frame,
            text="Password",
            font=("Segoe UI", 12),
            fg="white",
            bg="#1f2937"
        )
        password_label.pack(anchor="w")

        self.password_entry = tk.Entry(
            frame,
            font=("Segoe UI", 18),
            width=25,
            show="*"
        )
        self.password_entry.pack(pady=(5, 15))

        # OTP
        otp_label = tk.Label(
            frame,
            text="6-digit OTP",
            font=("Segoe UI", 12),
            fg="white",
            bg="#1f2937"
        )
        otp_label.pack(anchor="w")

        self.otp_entry = tk.Entry(
            frame,
            font=("Segoe UI", 24),
            justify="center",
            width=8
        )
        self.otp_entry.pack(pady=(5, 15))

        verify_button = tk.Button(
            frame,
            text="Verify OTP",
            font=("Segoe UI", 14, "bold"),
            padx=30,
            pady=10,
            command=self.verify
        )
        verify_button.pack(pady=20)

        self.status_label = tk.Label(
            frame,
            text="",
            font=("Segoe UI", 11),
            fg="#fca5a5",
            bg="#1f2937"
        )
        self.status_label.pack()

        info = tk.Label(
            frame,
            text="Prototype only — Windows authentication is still separate.",
            font=("Segoe UI", 10),
            fg="#9ca3af",
            bg="#1f2937"
        )
        info.pack(pady=(15, 0))

        # Enter key
        self.root.bind(
            "<Return>",
            lambda event: self.verify()
        )

        # Start with username selected
        self.username_entry.focus_set()

    def verify(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        otp = self.otp_entry.get().strip()

        # Basic local validation
        if not username:
            self.show_error("Please enter your username.")
            self.username_entry.focus_set()
            return

        if not password:
            self.show_error("Please enter your password.")
            self.password_entry.focus_set()
            return

        if len(otp) != 6 or not otp.isdigit():
            self.show_error("OTP must be exactly 6 digits.")
            self.otp_entry.delete(0, tk.END)
            self.otp_entry.focus_set()
            return

        self.status_label.config(
            text="Verifying...",
            fg="#fcd34d"
        )
        self.root.update_idletasks()

        try:
            # Send credentials to the local FastAPI server.
            data = urllib.parse.urlencode({
                "username": username,
                "password": password,
                "otp": otp,
            }).encode("utf-8")

            request = urllib.request.Request(
                GATE_URL,
                data=data,
                method="POST"
            )

            request.add_header(
                "Content-Type",
                "application/x-www-form-urlencoded"
            )

            with urllib.request.urlopen(
                request,
                timeout=10
            ) as response:

                response_body = response.read().decode("utf-8")
                result = json.loads(response_body)

            # Successful authentication
            if result.get("success") and result.get("url"):
                self.status_label.config(
                    text="Authentication successful.",
                    fg="#86efac"
                )
                self.root.update_idletasks()

                import webbrowser

                webbrowser.open(result["url"])

                self.root.destroy()
                return

            # Unexpected response
            self.show_error(
                result.get(
                    "message",
                    "Authentication failed."
                )
            )

        except urllib.error.HTTPError as error:
            try:
                body = error.read().decode("utf-8")
                result = json.loads(body)
                message = result.get(
                    "message",
                    "Authentication failed."
                )
            except Exception:
                message = "Authentication failed."

            self.show_error(message)

        except urllib.error.URLError:
            self.show_error(
                "Cannot connect to the OTP server.\n"
                "Check the OTP_GATE_URL setting and make sure the server is reachable."
            )

        except Exception:
            self.show_error(
                "Unable to contact the OTP authentication server."
            )

    def show_error(self, message):
        self.status_label.config(
            text=message,
            fg="#fca5a5"
        )

        self.otp_entry.delete(0, tk.END)
        self.otp_entry.focus_set()

    def block_close(self):
        # Prevent closing the gate window with X.
        pass


if __name__ == "__main__":
    root = tk.Tk()
    app = OTPGate(root)
    root.mainloop()