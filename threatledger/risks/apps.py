from django.apps import AppConfig


class RisksConfig(AppConfig):
    name = "threatledger.risks"
    label = "risks"
    verbose_name = "Risk register"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        from .schedules import ensure_schedules

        post_migrate.connect(ensure_schedules, sender=self)
