from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "threatledger.core"
    label = "core"
    verbose_name = "Core"

    def ready(self) -> None:
        from django.db.models.signals import post_migrate

        from .schedules import ensure_schedules

        post_migrate.connect(ensure_schedules, dispatch_uid="threatledger-schedules")
