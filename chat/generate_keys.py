import rsa

maria_pub, maria_priv = rsa.generate_keys()
joao_pub, joao_priv = rsa.generate_keys()

rsa.save_key(maria_pub, "maria_pub.key")
rsa.save_key(maria_priv, "maria_priv.key")

rsa.save_key(joao_pub, "joao_pub.key")
rsa.save_key(joao_priv, "joao_priv.key")

print("Chaves geradas.")