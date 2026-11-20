from django.contrib import admin
from django.urls import include, path

from threatledger.core.admin_site import restrict_admin_to_superusers

restrict_admin_to_superusers(admin.site)

urlpatterns = [
    path("", include("threatledger.core.urls")),
    path("accounts/", include("threatledger.accounts.urls")),
    path("audit/", include("threatledger.audit.urls")),
    path("attack/", include("threatledger.attack.urls")),
    path("risks/", include("threatledger.risks.urls")),
    path("controls/", include("threatledger.controls.urls")),
    path("frameworks/", include("threatledger.frameworks.urls")),
    path("coverage/", include("threatledger.coverage.urls")),
    path("reports/", include("threatledger.reporting.urls")),
    path("api/v1/", include("threatledger.core.api_urls")),
    path("admin/", admin.site.urls),
]

handler403 = "threatledger.core.views.permission_denied"
handler404 = "threatledger.core.views.page_not_found"
handler500 = "threatledger.core.views.server_error"
