from __future__ import annotations

from typing import Any

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from threatledger.accounts.permissions import AUTHENTICATED, capabilities, get_role


class MeView(APIView):
    """The authenticated user's identity, role and capabilities."""

    tl_access = AUTHENTICATED

    def get(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        user = request.user
        role = get_role(user)
        return Response(
            {
                "username": user.get_username(),
                "role": role.value if role else None,
                "capabilities": sorted(c.value for c in capabilities(user)),
            }
        )
