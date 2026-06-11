import threading
import time
import requests

from crypto_utils import create_packet, read_packet


class Cliente:

    def __init__(
        self,
        name,
        private_key,
        public_keys,
        server_url="http://127.0.0.1:5000"
    ):
        self.name = name
        self.private_key = private_key
        self.public_keys = public_keys
        self.server_url = server_url

    def send_message(self, receiver, message):

        receiver_pub = self.public_keys[receiver]

        packet = create_packet(
            message,
            self.name,
            self.private_key,
            receiver_pub
        )

        packet["receiver"] = receiver

        requests.post(
            f"{self.server_url}/send",
            json=packet
        )

    def fetch_messages(self):

        response = requests.get(
            f"{self.server_url}/messages/{self.name}"
        )

        packets = response.json()

        messages = []

        for packet in packets:

            sender = packet["sender"]

            try:

                plaintext = read_packet(
                    packet,
                    self.private_key,
                    self.public_keys[sender]
                )

                messages.append({
                    "sender": sender,
                    "message": plaintext
                })

            except Exception as e:

                messages.append({
                    "sender": sender,
                    "error": str(e)
                })

        return messages

    def start_receiver(self, interval=1):

        def receiver_loop():

            while True:

                try:

                    messages = self.fetch_messages()

                    for msg in messages:

                        if "error" in msg:

                            print(
                                f"\n[ERRO] {msg['error']}"
                            )

                        else:

                            print(
                                f"\n[{msg['sender']}] "
                                f"{msg['message']}"
                            )

                except Exception as e:

                    print(
                        f"\nErro ao receber mensagens: {e}"
                    )

                time.sleep(interval)

        threading.Thread(
            target=receiver_loop,
            daemon=True
        ).start()