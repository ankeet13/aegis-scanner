# Author : Sudip Ojha
"""
AEGIS Scanner — Web Crawler with Headless Browser Support
Discovers endpoints, forms, parameters, and API paths from a target URL.

Two crawling modes
1. HEADLESS BROWSER (Playwright) — renders JavaScript, handles SPAs,
   Angular, React, Vue apps. Intercepts network requests to discover
   API calls. Clicks interactive elements. This is similar to how
   Burp Suite's crawler works with its embedded Chromium engine.

2. STATIC HTML (requests + BeautifulSoup) — fallback mode when
   Playwright is not installed. Parses raw HTML only.

The crawler automatically uses Playwright if available, otherwise
falls back to static mode with a warning.

Install Playwright:
    pip install playwright
    playwright install chromium
"""

import re
import time
import logging
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
from bs4 import BeautifulSoup, Comment
from backend.config import MAX_CRAWL_DEPTH, MAX_URLS, IGNORED_EXTENSIONS
from backend.utils.http_client import HTTPClient

logger = logging.getLogger(__name__)

# Check if Playwright is available
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    logger.info("Playwright not installed — using static HTML crawling only.")
    logger.info("For JavaScript/SPA support: pip install playwright && playwright install chromium")


# Common web application paths to probe during crawling
COMMON_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/register", "/signup", "/sign-up",
    "/admin", "/administrator", "/admin/login",
    "/dashboard", "/panel", "/console",
    "/api", "/api/v1", "/api/v2",
    "/api/users", "/api/user", "/api/accounts",
    "/api/products", "/api/items", "/api/orders",
    "/api/search", "/api/config", "/api/settings",
    "/search", "/find", "/query",
    "/profile", "/account", "/settings", "/preferences",
    "/users", "/user", "/members",
    "/logout", "/signout",
    "/about", "/contact", "/help", "/faq",
    "/sitemap.xml", "/robots.txt",
    "/index.html", "/index.php", "/default.aspx",
    "/home", "/main", "/app",
    "/upload", "/uploads", "/files", "/media",
    "/download", "/downloads",
    "/test", "/debug", "/status", "/health",
    "/graphql", "/graphiql",
    "/swagger", "/api-docs", "/docs",
]


class Endpoint:
    """
    Represents a single discovered endpoint with its insertion points.
    """

    def __init__(self, url, method="GET", params=None, data=None,
                 param_names=None, is_form=False, form_fields=None):
        self.url = url
        self.method = method.upper()
        self.params = params or {}
        self.data = data or {}
        self.param_names = param_names or []
        self.is_form = is_form
        self.form_fields = form_fields or {}

    def to_dict(self):
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "data": self.data,
            "param_names": self.param_names,
            "is_form": self.is_form,
            "form_fields": self.form_fields,
        }

    def __repr__(self):
        return f"Endpoint({self.method} {self.url} params={self.param_names})"


class Crawler:
    """
    Enhanced crawler with headless browser support.
    Uses Playwright for JavaScript-rendered pages if available,
    falls back to static HTML parsing otherwise.
    """

    def __init__(self, http_client=None, use_browser=True):
        self.client = http_client or HTTPClient()
        self.visited = set()
        self.endpoints = []
        self.base_domain = None
        self.base_url = None
        self.use_browser = use_browser and PLAYWRIGHT_AVAILABLE
        # URLs discovered via network interception (Playwright only)
        self.intercepted_urls = set()

    def crawl(self, target_url, max_depth=None, max_urls=None):
        """
        Crawl the target URL and return discovered endpoints.
        """
        max_depth = max_depth or MAX_CRAWL_DEPTH
        max_urls = max_urls or MAX_URLS

        parsed = urlparse(target_url)
        self.base_domain = parsed.netloc
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.visited = set()
        self.endpoints = []
        self.intercepted_urls = set()

        queue = deque([(target_url, 0)])

        # Phase 1: Probe common paths
        logger.info(f"Crawler: probing common paths on {self.base_url}")
        common_urls = self._probe_common_paths()
        for url in common_urls:
            if url not in self.visited and len(self.visited) < max_urls:
                queue.append((url, 1))
        logger.info(f"Crawler: found {len(common_urls)} common paths")

        # Phase 2: Headless browser crawl (if available)
        if self.use_browser:
            logger.info("Crawler: using Playwright headless browser (JS enabled)")
            browser_urls = self._browser_crawl(target_url, max_depth, max_urls)
            for url in browser_urls:
                if url not in self.visited and len(self.visited) < max_urls:
                    queue.append((url, 1))
            logger.info(
                f"Crawler: browser discovered {len(browser_urls)} URLs "
                f"+ {len(self.intercepted_urls)} intercepted API calls"
            )
            # Add intercepted API calls to queue
            for url in self.intercepted_urls:
                if url not in self.visited and len(self.visited) < max_urls:
                    queue.append((url, 1))
        else:
            logger.info("Crawler: using static HTML mode (no JS rendering)")

        # Phase 3: BFS crawl (static HTML parsing for all discovered URLs)
        while queue and len(self.visited) < max_urls:
            url, depth = queue.popleft()
            url = self._normalize_url(url)

            if url in self.visited or depth > max_depth:
                continue
            if self._should_skip(url):
                continue

            self.visited.add(url)

            response = self.client.send_request(url)
            if response.error:
                continue

            # Handle redirects
            if response.status_code in (301, 302, 307, 308):
                location = self._get_header(response, "location")
                if location:
                    redirect_url = urljoin(url, location)
                    if self._is_same_domain(redirect_url) and redirect_url not in self.visited:
                        queue.append((redirect_url, depth))
                continue

            if response.status_code >= 400:
                continue

            # Register as endpoint
            query_params = parse_qs(urlparse(url).query)
            if query_params:
                flat_params = {k: v[0] for k, v in query_params.items()}
                self._add_endpoint(Endpoint(
                    url=url.split("?")[0],
                    method="GET",
                    params=flat_params,
                    param_names=list(flat_params.keys()),
                ))
            else:
                self._add_endpoint(Endpoint(url=url, method="GET"))

            # Parse HTML for links and forms
            if response.body:
                soup = BeautifulSoup(response.body, "html.parser")

                base_tag = soup.find("base", href=True)
                page_base = base_tag["href"] if base_tag else url

                links = set()
                links.update(self._extract_anchor_links(soup, page_base))
                links.update(self._extract_resource_links(soup, page_base))
                links.update(self._extract_form_actions(soup, page_base))
                links.update(self._extract_js_urls(soup, page_base))
                links.update(self._extract_comment_urls(soup, page_base))
                links.update(self._extract_data_attributes(soup, page_base))
                links.update(self._extract_meta_redirects(soup, page_base))

                for link in links:
                    if link not in self.visited and len(self.visited) < max_urls:
                        queue.append((link, depth + 1))

                forms = self._extract_forms(soup, page_base)
                for form_endpoint in forms:
                    self._add_endpoint(form_endpoint)

        return self.endpoints

    # ------------------------------------------------------------------
    # Playwright Headless Browser Crawl
    # ------------------------------------------------------------------
    def _browser_crawl(self, target_url, max_depth, max_urls):
        """
        Use Playwright to render pages with JavaScript execution.
        Intercepts network requests to discover API calls.
        Clicks interactive elements to trigger navigation.
        """
        discovered_urls = set()

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    user_agent="AEGIS-Scanner/1.0 (NIT6150 Academic Project)",
                    ignore_https_errors=True,
                )

                # Set auth cookies if the HTTP client has them
                if hasattr(self.client, 'session') and self.client.session.cookies:
                    cookies = []
                    for name, value in self.client.session.cookies.items():
                        cookies.append({
                            "name": name,
                            "value": value,
                            "domain": self.base_domain,
                            "path": "/",
                        })
                    if cookies:
                        context.add_cookies(cookies)

                page = context.new_page()

                # Intercept network requests to discover API calls
                def on_request(request):
                    url = request.url
                    if self._is_same_domain(url):
                        self.intercepted_urls.add(url)
                        # Extract query params from intercepted URLs
                        parsed = urlparse(url)
                        if parsed.query:
                            flat = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                            self._add_endpoint(Endpoint(
                                url=url.split("?")[0],
                                method=request.method,
                                params=flat,
                                param_names=list(flat.keys()),
                            ))

                page.on("request", on_request)

                # Visit pages with BFS
                pages_to_visit = deque([(target_url, 0)])
                browser_visited = set()

                while pages_to_visit and len(browser_visited) < min(max_urls, 30):
                    url, depth = pages_to_visit.popleft()

                    if url in browser_visited or depth > max_depth:
                        continue
                    if not self._is_same_domain(url):
                        continue

                    browser_visited.add(url)

                    try:
                        page.goto(url, wait_until="networkidle", timeout=15000)
                        # Wait for any dynamic content to load
                        page.wait_for_timeout(1500)
                    except Exception as e:
                        logger.debug(f"Browser: failed to load {url}: {e}")
                        continue

                    # Get the rendered HTML content
                    try:
                        content = page.content()
                    except Exception:
                        continue

                    # Extract all links from the rendered DOM
                    try:
                        links = page.eval_on_selector_all(
                            "a[href]",
                            "elements => elements.map(e => e.href)"
                        )
                        for link in links:
                            if self._is_same_domain(link):
                                clean = self._normalize_url(link)
                                discovered_urls.add(clean)
                                if depth + 1 <= max_depth:
                                    pages_to_visit.append((clean, depth + 1))
                    except Exception:
                        pass

                    # Extract form actions from rendered DOM
                    try:
                        forms = page.eval_on_selector_all(
                            "form",
                            """forms => forms.map(f => ({
                                action: f.action,
                                method: f.method || 'GET',
                                inputs: Array.from(f.querySelectorAll('input, textarea, select')).map(i => ({
                                    name: i.name,
                                    type: i.type || 'text',
                                    value: i.value || ''
                                })).filter(i => i.name)
                            }))"""
                        )
                        for form_data in forms:
                            action = form_data.get("action", url)
                            method = form_data.get("method", "GET").upper()
                            action_url = urljoin(url, action) if action else url

                            if not self._is_same_domain(action_url):
                                continue

                            fields = {}
                            param_names = []
                            for inp in form_data.get("inputs", []):
                                name = inp.get("name")
                                ftype = inp.get("type", "text").lower()
                                if name and ftype not in ("submit", "button", "image"):
                                    fields[name] = ftype
                                    param_names.append(name)

                            if param_names:
                                default_data = {n: "test" for n in param_names}
                                # Preserve hidden field values
                                for inp in form_data.get("inputs", []):
                                    if inp.get("type") == "hidden" and inp.get("name"):
                                        default_data[inp["name"]] = inp.get("value", "")

                                self._add_endpoint(Endpoint(
                                    url=action_url,
                                    method=method,
                                    params=default_data if method == "GET" else {},
                                    data=default_data if method == "POST" else {},
                                    param_names=param_names,
                                    is_form=True,
                                    form_fields=fields,
                                ))
                    except Exception:
                        pass

                    # Try clicking interactive elements to discover more routes
                    try:
                        clickables = page.query_selector_all(
                            "button:not([type='submit']), [role='button'], "
                            "[onclick], .nav-link, .menu-item, [routerlink], "
                            "[ng-click], [v-on\\:click], [@click]"
                        )
                        for elem in clickables[:10]:  # Limit clicks to avoid infinite loops
                            try:
                                elem.click(timeout=3000)
                                page.wait_for_timeout(500)
                                new_url = page.url
                                if new_url != url and self._is_same_domain(new_url):
                                    clean = self._normalize_url(new_url)
                                    discovered_urls.add(clean)
                                    if depth + 1 <= max_depth:
                                        pages_to_visit.append((clean, depth + 1))
                                # Go back to continue clicking other elements
                                page.goto(url, wait_until="networkidle", timeout=10000)
                                page.wait_for_timeout(500)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    # Extract URLs from the rendered page source
                    soup = BeautifulSoup(content, "html.parser")
                    js_urls = self._extract_js_urls(soup, url)
                    discovered_urls.update(js_urls)

                browser.close()

        except Exception as e:
            logger.error(f"Browser crawl failed: {e}")
            logger.info("Falling back to static HTML crawling")

        return discovered_urls

    # ------------------------------------------------------------------
    # Common path probing
    # ------------------------------------------------------------------
    def _probe_common_paths(self):
        """Probe common web application paths."""
        discovered = []
        for path in COMMON_PATHS:
            url = urljoin(self.base_url, path)
            response = self.client.send_request(url, allow_redirects=False)
            if response.error:
                continue
            if response.status_code == 200:
                discovered.append(url)
            elif response.status_code in (301, 302, 307, 308):
                location = self._get_header(response, "location")
                if location:
                    redirect_url = urljoin(url, location)
                    if self._is_same_domain(redirect_url):
                        discovered.append(redirect_url)
        return discovered

    # ------------------------------------------------------------------
    # Static HTML link extraction methods
    # ------------------------------------------------------------------
    def _extract_anchor_links(self, soup, base_url):
        links = set()
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if self._is_usable_href(href):
                absolute = urljoin(base_url, href)
                if self._is_same_domain(absolute):
                    links.add(self._normalize_url(absolute))
        return links

    def _extract_resource_links(self, soup, base_url):
        links = set()
        for tag in soup.find_all(
            ["script", "iframe", "img", "source", "video", "audio", "embed"],
            src=True
        ):
            src = tag["src"].strip()
            absolute = urljoin(base_url, src)
            if self._is_same_domain(absolute) and not self._should_skip(absolute):
                links.add(self._normalize_url(absolute))

        for tag in soup.find_all("link", href=True):
            href = tag["href"].strip()
            rel = tag.get("rel", [])
            if isinstance(rel, list):
                rel = " ".join(rel)
            if "stylesheet" not in rel and "icon" not in rel:
                absolute = urljoin(base_url, href)
                if self._is_same_domain(absolute):
                    links.add(self._normalize_url(absolute))
        return links

    def _extract_form_actions(self, soup, base_url):
        links = set()
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and action != "#":
                absolute = urljoin(base_url, action)
                if self._is_same_domain(absolute):
                    links.add(self._normalize_url(absolute))
        return links

    def _extract_js_urls(self, soup, base_url):
        links = set()
        for script in soup.find_all("script"):
            if not script.string:
                continue
            js = script.string

            # Quoted paths
            for pattern in [
                r'["\'](/[a-zA-Z0-9_/\-\.]+(?:\?[a-zA-Z0-9_=&]+)?)["\']',
                r'["`](/[a-zA-Z0-9_/\-\.]+(?:\?[a-zA-Z0-9_=&]+)?)["`]',
            ]:
                for path in re.findall(pattern, js):
                    if path.startswith("//") or len(path) < 2:
                        continue
                    if any(path.endswith(ext) for ext in (".js", ".css", ".png", ".jpg", ".svg")):
                        continue
                    absolute = urljoin(base_url, path)
                    if self._is_same_domain(absolute):
                        links.add(absolute)

            # Full URLs
            for full_url, _ in re.findall(
                r'["\']((https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9._/\-?=&%]+)?))["\']', js
            ):
                if self._is_same_domain(full_url):
                    links.add(self._normalize_url(full_url))

            # fetch/axios calls
            for path in re.findall(
                r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\']([^"\']+)["\']', js
            ):
                absolute = urljoin(base_url, path)
                if self._is_same_domain(absolute):
                    links.add(absolute)

            # window.location
            for path in re.findall(
                r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', js
            ):
                absolute = urljoin(base_url, path)
                if self._is_same_domain(absolute):
                    links.add(absolute)

        return links

    def _extract_comment_urls(self, soup, base_url):
        links = set()
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            for path in re.findall(r'(/[a-zA-Z0-9_/\-\.]+)', str(comment)):
                if len(path) > 1 and not any(path.endswith(e) for e in (".js", ".css", ".png")):
                    absolute = urljoin(base_url, path)
                    if self._is_same_domain(absolute):
                        links.add(absolute)
            for url in re.findall(r'https?://[a-zA-Z0-9._/\-?=&%]+', str(comment)):
                if self._is_same_domain(url):
                    links.add(self._normalize_url(url))
        return links

    def _extract_data_attributes(self, soup, base_url):
        links = set()
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if not isinstance(attr_value, str):
                    continue
                if attr_name.startswith("data-") or attr_name in (
                    "ng-href", "v-bind:href", "router-link"
                ):
                    if attr_value.startswith(("/", "http")):
                        absolute = urljoin(base_url, attr_value)
                        if self._is_same_domain(absolute):
                            links.add(self._normalize_url(absolute))
        return links

    def _extract_meta_redirects(self, soup, base_url):
        links = set()
        for meta in soup.find_all("meta", attrs={"http-equiv": True}):
            if meta.get("http-equiv", "").lower() == "refresh":
                content = meta.get("content", "")
                match = re.search(r'url\s*=\s*["\']?([^"\';\s]+)', content, re.IGNORECASE)
                if match:
                    absolute = urljoin(base_url, match.group(1))
                    if self._is_same_domain(absolute):
                        links.add(self._normalize_url(absolute))
        return links

    # ------------------------------------------------------------------
    # Form extraction
    # ------------------------------------------------------------------
    def _extract_forms(self, soup, base_url):
        form_endpoints = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            action_url = urljoin(base_url, action) if action else base_url

            if not self._is_same_domain(action_url):
                continue

            fields = {}
            param_names = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                field_type = inp.get("type", "text").lower()
                if field_type in ("submit", "button", "image"):
                    continue
                fields[name] = field_type
                param_names.append(name)

            if param_names:
                default_data = {name: "test" for name in param_names}
                for inp in form.find_all("input", {"type": "hidden"}):
                    hname = inp.get("name")
                    hvalue = inp.get("value", "")
                    if hname:
                        default_data[hname] = hvalue

                form_endpoints.append(Endpoint(
                    url=action_url,
                    method=method,
                    params=default_data if method == "GET" else {},
                    data=default_data if method == "POST" else {},
                    param_names=param_names,
                    is_form=True,
                    form_fields=fields,
                ))
        return form_endpoints

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _add_endpoint(self, endpoint):
        key = f"{endpoint.method}:{endpoint.url}:{sorted(endpoint.param_names)}"
        existing = {
            f"{e.method}:{e.url}:{sorted(e.param_names)}" for e in self.endpoints
        }
        if key not in existing:
            self.endpoints.append(endpoint)

    def _normalize_url(self, url):
        parsed = urlparse(url)
        return parsed._replace(fragment="").geturl()

    def _is_same_domain(self, url):
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def _should_skip(self, url):
        path = urlparse(url).path.lower()
        return any(path.endswith(ext) for ext in IGNORED_EXTENSIONS)

    def _is_usable_href(self, href):
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return False
        return True

    def _get_header(self, response, header_name):
        for key, value in response.headers.items():
            if key.lower() == header_name.lower():
                return value
        return None

    # ------------------------------------------------------------------
    # Public query methods
    # ------------------------------------------------------------------
    def get_login_forms(self):
        login_forms = []
        for ep in self.endpoints:
            if not ep.is_form:
                continue
            if any(ftype == "password" for ftype in ep.form_fields.values()):
                login_forms.append(ep)
        return login_forms

    def get_api_endpoints(self):
        return [ep for ep in self.endpoints if "/api/" in ep.url or "/api" in ep.url]

    def get_parameterized_endpoints(self):
        return [ep for ep in self.endpoints if ep.param_names]

    def get_stats(self):
        return {
            "urls_visited": len(self.visited),
            "endpoints_discovered": len(self.endpoints),
            "forms_found": len([e for e in self.endpoints if e.is_form]),
            "parameterized_endpoints": len(self.get_parameterized_endpoints()),
            "login_forms": len(self.get_login_forms()),
            "api_endpoints": len(self.get_api_endpoints()),
            "browser_mode": self.use_browser,
            "intercepted_api_calls": len(self.intercepted_urls),
        }