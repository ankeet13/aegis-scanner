# Author: Shristi — HTTP Client Module

import time
import requests
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from backend.config import (
    REQUEST_TIMEOUT,
    REQUEST_DELAY,
    DEFAULT_HEADERS,
    MAX_RETRIES,
)


class Response:
    """Lightweight wrapper around a raw HTTP response for analysis."""

    def __init__(self, status_code, headers, body, elapsed_ms, url, error=None):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.body_length = len(body) if body else 0
        self.elapsed_ms = elapsed_ms
        self.url = url
        self.error = error

    def to_dict(self):
        return {
            "status_code": self.status_code,
            "body_length": self.body_length,
            "elapsed_ms": round(self.elapsed_ms, 2),
            "url": self.url,
            "error": self.error,
        }


class HTTPClient:
    """
    Handles all outbound HTTP requests for the scanner.

    Key concept (from Burp Suite):
    - Every scan starts with a BASELINE request (original, unmodified)
    - Attack requests inject payloads into specific INSERTION POINTS
    - The Response objects are compared by the ResponseAnalyzer
    """

    def __init__(self, auth_cookie=None, custom_headers=None):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if custom_headers:
            self.session.headers.update(custom_headers)
        if auth_cookie:
            self.session.cookies.update(auth_cookie)
        self.session.verify = False  # allow self-signed certs for testing
        # Suppress InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )

    def send_request(self, url, method="GET", params=None, data=None,
                     headers=None, cookies=None, timeout=None, allow_redirects=True):
        """
        Send a single HTTP request and return a Response wrapper.
        This is the lowest-level method — all other methods use this.
        """
        timeout = timeout or REQUEST_TIMEOUT
        merged_headers = dict(self.session.headers)
        if headers:
            merged_headers.update(headers)

        for attempt in range(MAX_RETRIES + 1):
            try:
                start = time.time()
                raw = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    headers=merged_headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                )
                elapsed_ms = (time.time() - start) * 1000

                return Response(
                    status_code=raw.status_code,
                    headers=dict(raw.headers),
                    body=raw.text,
                    elapsed_ms=elapsed_ms,
                    url=str(raw.url),
                )

            except requests.exceptions.Timeout:
                elapsed_ms = (time.time() - start) * 1000
                if attempt == MAX_RETRIES:
                    return Response(
                        status_code=0,
                        headers={},
                        body="",
                        elapsed_ms=elapsed_ms,
                        url=url,
                        error="timeout",
                    )

            except requests.exceptions.ConnectionError:
                if attempt == MAX_RETRIES:
                    return Response(
                        status_code=0,
                        headers={},
                        body="",
                        elapsed_ms=0,
                        url=url,
                        error="connection_error",
                    )

            except requests.exceptions.RequestException as e:
                return Response(
                    status_code=0,
                    headers={},
                    body="",
                    elapsed_ms=0,
                    url=url,
                    error=str(e),
                )

            time.sleep(REQUEST_DELAY)

    def send_baseline(self, url, method="GET", params=None, data=None):
        """
        Send the original, unmodified request to establish a baseline response.
        Every scanner calls this first before injecting payloads.
        """
        return self.send_request(url=url, method=method, params=params, data=data)

    def send_attack(self, url, method="GET", params=None, data=None,
                    injection_param=None, payload=None):
        """
        Send a request with a payload injected into a specific insertion point.

        Args:
            url: Target URL
            method: HTTP method
            params: Original query parameters (dict)
            data: Original POST body (dict)
            injection_param: The parameter name to inject into
            payload: The attack payload string

        Returns:
            Response object with the attack result
        """
        attack_params = dict(params) if params else {}
        attack_data = dict(data) if data else {}

        if method.upper() == "GET" and injection_param:
            attack_params[injection_param] = payload
        elif method.upper() == "POST" and injection_param:
            attack_data[injection_param] = payload

        time.sleep(REQUEST_DELAY)

        return self.send_request(
            url=url,
            method=method,
            params=attack_params if method.upper() == "GET" else params,
            data=attack_data if method.upper() == "POST" else data,
        )

    def send_without_auth(self, url, method="GET", params=None, data=None):
        """
        Send a request with NO authentication cookies.
        Used by the BAC scanner to test if endpoints are accessible without auth.
        """
        no_auth_session = requests.Session()
        no_auth_session.headers.update(DEFAULT_HEADERS)

        try:
            start = time.time()
            raw = no_auth_session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                timeout=REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            elapsed_ms = (time.time() - start) * 1000

            return Response(
                status_code=raw.status_code,
                headers=dict(raw.headers),
                body=raw.text,
                elapsed_ms=elapsed_ms,
                url=str(raw.url),
            )
        except requests.exceptions.RequestException as e:
            return Response(
                status_code=0, headers={}, body="",
                elapsed_ms=0, url=url, error=str(e),
            )

    def send_timed_attack(self, url, method="GET", params=None, data=None,
                          injection_param=None, payload=None, timeout=None):
        """
        Send an attack request specifically for time-based blind detection.
        Uses a longer timeout to allow SLEEP() payloads to complete.
        """
        timeout = timeout or (REQUEST_TIMEOUT + 10)

        attack_params = dict(params) if params else {}
        attack_data = dict(data) if data else {}

        if method.upper() == "GET" and injection_param:
            attack_params[injection_param] = payload
        elif method.upper() == "POST" and injection_param:
            attack_data[injection_param] = payload

        time.sleep(REQUEST_DELAY)

        return self.send_request(
            url=url,
            method=method,
            params=attack_params if method.upper() == "GET" else params,
            data=attack_data if method.upper() == "POST" else data,
            timeout=timeout,
        )