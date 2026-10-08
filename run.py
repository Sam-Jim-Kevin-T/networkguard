import os

from networkguard import create_app

app = create_app()


if __name__ == "__main__":
    host = os.getenv("NETWORKGUARD_HOST", "127.0.0.1")
    cert_file = os.getenv("NETWORKGUARD_TLS_CERT")
    key_file = os.getenv("NETWORKGUARD_TLS_KEY")
    if host not in ("127.0.0.1", "::1", "localhost"):
        if not cert_file or not key_file:
            raise RuntimeError(
                "A TLS certificate and key are required when NETWORKGUARD_HOST is not loopback."
            )
        app.run(host=host, ssl_context=(cert_file, key_file))
    else:
        app.run(host=host)
