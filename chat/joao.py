import rsa

from cliente import Cliente


joao = Cliente(
    "joao",
    rsa.load_key("joao_priv.key"),
    {
        "maria": rsa.load_key("maria_pub.key"),
        "joao": rsa.load_key("joao_pub.key")
    }
)

joao.start_receiver()

while True:

    text = input("João > ")

    if text.strip():

        joao.send_message(
            "maria",
            text
        )