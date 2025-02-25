from OpenSSL import crypto
from datetime import datetime, timedelta

def generate_self_signed_cert():
    # Gerar par de chaves
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Criar certificado
    cert = crypto.X509()
    cert.get_subject().CN = "localhost"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Válido por um ano
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # Salvar certificado e chave privada
    with open("cert.pem", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    with open("key.pem", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == '__main__':
    generate_self_signed_cert()
