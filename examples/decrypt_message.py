import rsa


def main() -> None:
    with open("private.pem", "rb") as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    with open("encrypted.message", "rb") as f:
        message = f.read()

    decrypted_message = rsa.decrypt(message, private_key)

    print(decrypted_message)

    with open("decrypted.message", "wb") as f:
        f.write(decrypted_message)


if __name__ == "__main__":
    main()
