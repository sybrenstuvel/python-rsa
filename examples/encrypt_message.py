import rsa


def main() -> None:
    with open("public.pem", "rb") as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    message = b"Hello World!"

    encrypted_message = rsa.encrypt(message, public_key)

    print(encrypted_message.decode())

    with open("encrypted.message", "wb") as f:
        f.write(encrypted_message)


if __name__ == "__main__":
    main()
