"""View decorators for operator authentication and authorization.

These decorators enforce authentication and role-based access at the view layer.
Permission checks are always server-side — UI hiding is supplementary only.

Usage notes:
  - Works on both function-based views and class-based view methods.
  - When decorating a CBV method (def get/post on a View subclass), Django passes
    (self, request, ...) so the decorator inspects args[0] to find the real request.
"""

import functools

from django.http import HttpResponse
from django.shortcuts import redirect
from django.views import View

from apps.operators import sessions as sessions_module
from apps.operators.models import Operator


def _extract_request(args):
    """Return (maybe_self, request, rest_args) from args.

    For a CBV method, args = (self, request, ...).
    For an FBV, args = (request, ...).
    """
    if args and isinstance(args[0], View):
        # CBV: first arg is the view instance
        return args[0], args[1], args[2:]
    # FBV or standalone call
    return None, args[0], args[1:]


def _get_operator(request):
    """Resolve the operator from the session, or return None."""
    operator_id = request.session.get("operator_id")
    if not operator_id:
        return None
    try:
        op = Operator.objects.get(pk=operator_id)
    except Operator.DoesNotExist:
        return None
    if not op.is_active:
        return None
    return op


def _is_htmx(request):
    return request.headers.get("HX-Request") == "true"


def require_operator(view_func):
    """Ensure a valid, active operator session exists.

    Attaches ``request.operator`` and touches the session idle timer.
    HTMX requests receive a 401; browser requests are redirected to login.
    Works for both FBV and CBV methods (detects self automatically).
    """

    @functools.wraps(view_func)
    def _wrapped(*args, **kwargs):
        view_self, request, rest = _extract_request(args)
        op = _get_operator(request)
        if op is None:
            if _is_htmx(request):
                return HttpResponse("Unauthorized", status=401)
            return redirect("/auth/login/")
        request.operator = op
        # Touch the idle auto-lock timer (sessions module manages the in-process holder)
        try:
            sessions_module.touch()
        except Exception:  # noqa: BLE001, S110
            pass  # touch() is best-effort; never block a request on it
        if view_self is not None:
            return view_func(view_self, request, *rest, **kwargs)
        return view_func(request, *rest, **kwargs)

    return _wrapped


def require_admin(view_func):
    """Ensure the operator is an Administrator.

    Applies ``require_operator`` first, then checks role.
    HTMX requests receive a 403; browser requests receive a 403 response.
    Works for both FBV and CBV methods (detects self automatically).
    """

    @functools.wraps(view_func)
    @require_operator
    def _wrapped(*args, **kwargs):
        view_self, request, rest = _extract_request(args)
        if request.operator.role != Operator.Role.ADMINISTRATOR:
            if _is_htmx(request):
                return HttpResponse("Forbidden", status=403)
            return HttpResponse("Forbidden — Administrator role required.", status=403)
        if view_self is not None:
            return view_func(view_self, request, *rest, **kwargs)
        return view_func(request, *rest, **kwargs)

    return _wrapped
