from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "threatledger.accounts"
    label = "accounts"
    verbose_name = "Accounts"

    def ready(self) -> None:
        from . import signals  # noqa: F401
