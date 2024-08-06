import rsa


def main() -> None:
    with open('public.pem', 'rb') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open('private.pem', 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    print(public_key, private_key, sep='\n')


if __name__ == '__main__':
    main()
