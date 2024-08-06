import rsa


def main() -> None:
    """
    You can save keys in 2 formats: PEM, DER
    """
    for key in rsa.new_keys(1024):
        with open(f"{key.__class__.__name__[:-3].lower()}.pem", "wb") as f:
            f.write(key.save_pkcs1("PEM"))


if __name__ == "__main__":
    main()
