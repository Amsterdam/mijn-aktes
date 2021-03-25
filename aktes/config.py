import os
import os.path


BASE_PATH = os.path.abspath(os.path.dirname(__file__))


def get_sentry_dsn():
    return os.getenv('SENTRY_DSN', None)


def get_aktes_username():
    return os.getenv("AKTES_USERNAME")


def get_aktes_password():
    return os.getenv("AKTES_PASSWORD")


def get_aktes_api_host():
    return os.getenv("AKTES_API_HOST")


def get_key():
    return os.getenv("FERNET_KEY")


def get_tma_certificate():
    tma_cert_location = os.getenv('TMA_CERTIFICATE')
    with open(tma_cert_location) as f:
        return f.read()
