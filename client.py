import flet as ft
import socket
import threading
import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Message:
    def __init__(self, user_name: str, text: str, message_type: str):
        self.user_name = user_name
        self.text = text
        self.message_type = message_type


class ChatClient:
    def __init__(self, page: ft.Page):
        self.page = page
        self.chat = ft.ListView(
            expand=True,
            spacing=10,
            auto_scroll=True,
        )

        self.new_message = ft.TextField(
            hint_text="Write a message...",
            autofocus=True,
            shift_enter=True,
            min_lines=1,
            max_lines=5,
            filled=True,
            expand=True,
            on_submit=self.send_message_click,
        )

        self.username = ""
        self.password = ""
        self.key = None
        self.client_socket = None

        # Setup initial dialog
        self.join_user_name = ft.TextField(
            label="Enter your name to join the chat",
            autofocus=True,
            on_submit=self.join_chat_click,
        )
        self.page.dialog = ft.AlertDialog(
            open=True,
            modal=True,
            title=ft.Text("Welcome!"),
            content=ft.Column([self.join_user_name], width=300, height=70, tight=True),
            actions=[ft.ElevatedButton(text="Join chat", on_click=self.join_chat_click)],
            actions_alignment=ft.MainAxisAlignment.END,
        )

    def derive_key(self, password):
        """Derives a 32-byte key from the password."""
        salt = b'\x00' * 16
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_message(self, message):
        """Encrypts the message with AES."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypts the incoming AES-encrypted message."""
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
        return decrypted_message.decode()

    def join_chat_click(self, e):
        if not self.join_user_name.value:
            self.join_user_name.error_text = "Name cannot be blank!"
            self.join_user_name.update()
        else:
            self.username = self.join_user_name.value
            self.password = getpass.getpass("Enter encryption password: ")
            self.key = self.derive_key(self.password)
            self.page.session.set("user_name", self.username)
            self.page.dialog.open = False

            # Setup socket connection
            server_input = input("Enter server address (e.g., '127.0.0.1:5555' or 'chatserver.com'): ")
            if ':' in server_input:
                host, port = server_input.split(':')
                port = int(port)
            else:
                host = server_input
                port = int(input("Enter server port (e.g., 5555): "))
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))

            # Send username to the server
            self.client_socket.send(self.username.encode())
            
            self.page.pubsub.send_all(
                Message(self.username, f"{self.username} has joined the chat.", "login_message")
            )
            self.page.update()

            # Start the receive thread
            threading.Thread(target=self.receive_messages, daemon=True).start()

    def send_message_click(self, e):
        message = self.new_message.value
        if message != "":
            encrypted_message = self.encrypt_message(message)
            self.client_socket.send(encrypted_message)
            self.page.pubsub.send_all(
                Message(self.username, message, "chat_message")
            )
            self.new_message.value = ""
            self.new_message.focus()
            self.page.update()

    def receive_messages(self):
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
            
            # Ensure that the data received is properly handled as binary.
            # The data is already encrypted, so we need to decrypt it.
                try:
                    decrypted_message = self.decrypt_message(data)
                    self.page.pubsub.send_all(
                        Message("Server", decrypted_message, "chat_message")
                )
                except Exception as e:
                # If decryption fails, display an error
                    self.page.pubsub.send_all(
                        Message("System", f"Error decrypting message: {e}", "login_message")
                )
            
            except Exception as e:
            # If there's an error in receiving the data
                self.page.pubsub.send_all(
                    Message("System", f"Error receiving message: {e}", "login_message")
            )
                break


    def on_message(self, message: Message):
        """Handle incoming messages and update the chat UI."""
        if message.message_type == "chat_message":
            self.chat.controls.append(ChatMessage(message))
        elif message.message_type == "login_message":
            self.chat.controls.append(ft.Text(message.text, italic=True, color=ft.colors.BLACK45, size=12))
        self.page.update()

    def setup_ui(self):
        """Sets up the UI elements."""
        self.page.add(
            ft.Container(
                content=self.chat,
                border=ft.border.all(1, ft.colors.OUTLINE),
                border_radius=5,
                padding=10,
                expand=True,
            ),
            ft.Row(
                [
                    self.new_message,
                    ft.IconButton(
                        icon=ft.icons.SEND_ROUNDED,
                        tooltip="Send message",
                        on_click=self.send_message_click,
                    ),
                ]
            ),
        )

    def run(self):
        """Start the UI and subscribe to pubsub messages."""
        self.page.pubsub.subscribe(self.on_message)
        self.setup_ui()


class ChatMessage(ft.Row):
    """Displays individual chat messages."""
    def __init__(self, message: Message):
        super().__init__()
        self.vertical_alignment = ft.CrossAxisAlignment.START
        self.controls = [
            ft.CircleAvatar(
                content=ft.Text(message.user_name[:1].capitalize()),
                color=ft.colors.WHITE,
                bgcolor=ft.colors.BLUE,
            ),
            ft.Column(
                [
                    ft.Text(message.user_name, weight="bold"),
                    ft.Text(message.text, selectable=True),
                ],
                tight=True,
                spacing=5,
            ),
        ]


def main(page: ft.Page):
    client = ChatClient(page)
    client.run()


ft.app(target=main)
