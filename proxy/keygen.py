"""Genera una clave de cifrado Fernet para PROXY_ENCRYPTION_KEY.

Uso:
    python -m proxy.keygen
"""

from cryptography.fernet import Fernet


def main() -> None:
    print(Fernet.generate_key().decode())


if __name__ == "__main__":
    main()
