import ipaddress
from typing import Optional


def get_client_ip(request) -> Optional[str]:
    """
    Extract client IP address from Django request object.
    Safely handles proxies and load balancers.
    """

    if request is None:
        return None

    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")

    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2
        # The first one is the real client IP
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")

    if ip:
        try:
            # Validate both IP formats
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            return None

    return None