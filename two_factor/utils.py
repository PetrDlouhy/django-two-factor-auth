from urllib.parse import quote, urlencode

from django.conf import settings
from django.utils.module_loading import import_string
from django_otp import devices_for_user
from django_otp.plugins.otp_static.models import StaticDevice

USER_DEFAULT_DEVICE_ATTR_NAME = "_default_device"


def default_device(user, confirmed=True):
    """Return the user's primary device, or ``None``.

    The selection policy is pluggable via
    ``TWO_FACTOR_DEFAULT_DEVICE_PICKER``; see
    :func:`_pick_default_device` for the built-in one. Positive results
    are cached on the user instance, negative ones are not.
    """
    if not user or user.is_anonymous:
        return None
    if hasattr(user, USER_DEFAULT_DEVICE_ATTR_NAME):
        return getattr(user, USER_DEFAULT_DEVICE_ATTR_NAME)

    devices = list(devices_for_user(user, confirmed=confirmed))
    chosen = _get_default_device_picker()(devices)
    if chosen is not None:
        setattr(user, USER_DEFAULT_DEVICE_ATTR_NAME, chosen)
    return chosen


def _get_default_device_picker():
    """Resolve ``TWO_FACTOR_DEFAULT_DEVICE_PICKER``, or the built-in policy.

    Resolved per call so ``override_settings`` works.
    """
    path = getattr(settings, 'TWO_FACTOR_DEFAULT_DEVICE_PICKER', None)
    return import_string(path) if path else _pick_default_device


def primary_device_candidates(devices):
    """Return ``devices`` without backup devices, in the original order.

    Excludes :class:`~django_otp.plugins.otp_static.models.StaticDevice`
    and devices named ``'backup'``, matching the convention used by
    :func:`~two_factor.plugins.phonenumber.utils.backup_phones`. Public
    so custom pickers can reuse it.
    """
    return [
        d for d in devices
        if not isinstance(d, StaticDevice) and d.name != 'backup'
    ]


def _pick_default_device(devices):
    """Built-in policy: named 'default', else most recently used, else stable.

    A device named ``'default'`` always wins, so deployments relying on
    the setup wizard's naming keep their current behaviour.

    Otherwise the most recently used device wins. ``last_used_at`` comes
    from django-otp's ``TimestampMixin`` (django-otp >= 1.4), which not
    every device model uses -- notably
    :class:`~two_factor.plugins.phonenumber.models.PhoneDevice` does not.
    Devices without it can never win on recency and fall through to the
    tie-break below, so on a mix of timestamped and untimestamped
    devices the timestamped ones are always preferred. See the
    ``TWO_FACTOR_DEFAULT_DEVICE_PICKER`` docs.

    The tie-break is the lowest ``persistent_id``, compared as a string,
    which makes the choice stable across requests rather than dependent
    on device iteration order.
    """
    candidates = primary_device_candidates(devices)

    for device in candidates:
        if device.name == 'default':
            return device

    used = [d for d in candidates if getattr(d, 'last_used_at', None) is not None]
    if used:
        return max(used, key=lambda d: d.last_used_at)

    if candidates:
        return min(candidates, key=lambda d: d.persistent_id)

    return None


def get_otpauth_url(accountname, secret, issuer=None, digits=None):
    # For a complete run-through of all the parameters, have a look at the
    # specs at:
    # https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    # quote and urlencode work best with bytes, not unicode strings.
    accountname = accountname.encode('utf8')
    issuer = issuer.encode('utf8') if issuer else None

    label = quote(b': '.join([issuer, accountname]) if issuer else accountname)

    # Ensure that the secret parameter is the FIRST parameter of the URI, this
    # allows Microsoft Authenticator to work.
    query = [
        ('secret', secret),
        ('digits', digits or totp_digits())
    ]

    if issuer:
        query.append(('issuer', issuer))

    return 'otpauth://totp/%s?%s' % (label, urlencode(query))


# from http://mail.python.org/pipermail/python-dev/2008-January/076194.html
def monkeypatch_method(cls):
    def decorator(func):
        setattr(cls, func.__name__, func)
        return func
    return decorator


def totp_digits():
    """
    Returns the number of digits (as configured by the TWO_FACTOR_TOTP_DIGITS setting)
    for totp tokens. Defaults to 6
    """
    return getattr(settings, 'TWO_FACTOR_TOTP_DIGITS', 6)
