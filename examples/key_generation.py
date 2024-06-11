import rsa


def main() -> None:
    """
    Here is an example of 1024, but you can also use a bit rate equal to 128, 256, 384, 512, 1024, 2048, 3072, 4096
    """
    public_key, private_key = rsa.new_keys(128)

    print(private_key)


if __name__ == '__main__':
    main()
