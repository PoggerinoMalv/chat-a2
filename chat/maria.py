import rsa

from cliente import Cliente


maria = Cliente(
    "maria",
    rsa.load_key("maria_priv.key"),
    {
        "maria": rsa.load_key("maria_pub.key"),
        "joao": rsa.load_key("joao_pub.key")
    }
)

maria.start_receiver()

while True:

    text = input("Maria > ")

    if text.strip():

        maria.send_message(
            "joao",
            text
        )