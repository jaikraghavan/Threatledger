from django.apps import AppConfig


class ApiConfig(AppConfig):
    name = "threatledger.api"
    label = "api"
    verbose_name = "API"

    def ready(self) -> None:
        from . import schema  # noqa: F401 - registers the OpenAPI auth extension
