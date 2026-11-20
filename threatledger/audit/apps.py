from django.apps import AppConfig


class AuditConfig(AppConfig):
    name = "threatledger.audit"
    label = "audit"
    verbose_name = "Audit log"
