"""
Dark Web Spider — multithreaded, recursive .onion crawler with keyword matching.

This module provides two main classes:

- ``DarkWebMonitor`` — base crawler that fetches pages via Tor, extracts links,
  and detects JS-rendered pages for Playwright fallback.

- ``PersistentDarkWebMonitor`` — extends the base with SQLite-backed persistence,
  parallel scanning via ThreadPoolExecutor, and graceful shutdown support.

Typical usage::

    from spider import PersistentDarkWebMonitor

    monitor = PersistentDarkWebMonitor()
    monitor.run_automated_scan()

For a simpler entry point, use ``auto_spider.py`` which handles Tor startup
and identity rotation automatically.
"""

import queue as _queue
import concurrent.futures
import requests
from requests.exceptions import RequestException
from typing import List, Optional, Tuple, Dict
import time
import logging
import os
import sys
import threading
import re
from bs4 import BeautifulSoup
from core import config
from core.tor_manager import start_tor_service
from core.db_manager import DatabaseManager
from core.link_validator import OnionValidator

# Playwright is an optional dependency — imported lazily so the spider
# still works if binaries haven't been installed yet.
try:
    from playwright.sync_api import sync_playwright, Browser as PWBrowser
    from playwright_stealth import Stealth as PWS
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    sync_playwright = None  # type: ignore[assignment,call-arg]
    PWS = None              # type: ignore[assignment,call-arg]
    _PLAYWRIGHT_AVAILABLE = False

# Configure logging
# Note: link_validator also configures logging, but basicConfig only takes effect once.
if not logging.getLogger().hasHandlers():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler() # Output to console
        ]
    )


_TAG_RE = re.compile(r'<[^>]+>')

# ── JS-detection signals ───────────────────────────────────────────────────────
_JS_SIGNALS = re.compile(
    r'React\.createElement'
    r'|Vue\.createApp'
    r'|__NEXT_DATA__'
    r'|__nuxt'
    r'|angular\.module',
    re.IGNORECASE,
)

def _is_js_rendered(html: str) -> bool:
    """Return True if the page looks like a JS shell needing browser rendering.

    Heuristics (any one is sufficient to trigger the fallback):
      - Visible body text is below the configured threshold
      - A <noscript> tag is present
      - Known JS-framework markers found in the raw source
      - The <body> contains no block-level content elements at all
    """
    soup = BeautifulSoup(html, 'html.parser')

    # 1. Thin body text
    body = soup.find('body')
    body_text = body.get_text(separator=' ', strip=True) if body else ''
    if len(body_text) < config.JS_FALLBACK_BODY_THRESHOLD:
        return True

    # 2. <noscript> tag present
    if soup.find('noscript'):
        return True

    # 3. JS framework fingerprints in raw source
    if _JS_SIGNALS.search(html):
        return True

    # 4. Body has no block-level elements at all
    if body and not body.find(['p', 'div', 'table', 'article', 'section', 'main']):
        return True

    return False


def _extract_context(text: str, start: int, end: int, window: int = 50) -> str:
    """Return a clean ~100-char snippet surrounding a match position.

    Strips HTML tags and collapses whitespace so the stored context is
    human-readable plain text rather than raw markup.
    """
    snippet_start = max(0, start - window)
    snippet_end   = min(len(text), end + window)
    raw = text[snippet_start:snippet_end]
    clean = _TAG_RE.sub(' ', raw)
    clean = ' '.join(clean.split())
    return clean[:200]


class _PlaywrightWorker(threading.Thread):
    """Dedicated daemon thread that owns the Playwright browser process.

    Playwright's sync_api uses greenlets, which are thread-local — you cannot
    call browser/page methods from a different OS thread than the one that
    called sync_playwright().start().  This worker serialises all Playwright
    work into a single thread while letting spider workers stay non-blocking.

    Usage::
        worker = _PlaywrightWorker()
        html = worker.fetch('http://example.onion')   # blocks until done
        worker.shutdown()
    """

    _SENTINEL = object()  # poison pill for the run-loop

    def __init__(self):
        super().__init__(daemon=True, name='playwright-worker')
        self._q: _queue.Queue = _queue.Queue()
        self._ready = threading.Event()   # set once the browser is up
        self._error: Optional[Exception] = None
        self.start()
        # Wait for the browser to become ready (or fail) before returning
        if not self._ready.wait(timeout=60):
            raise RuntimeError('[PW] Playwright browser did not start within 60 s')
        if self._error:
            raise self._error

    def run(self):
        """Own the full Playwright lifecycle in this thread."""
        if not _PLAYWRIGHT_AVAILABLE:
            self._error = RuntimeError('[PW] playwright not installed')
            self._ready.set()
            return
        try:
            with sync_playwright() as pw:  # type: ignore[misc]
                browser = pw.chromium.launch(
                    headless=True,
                    proxy={'server': 'socks5://127.0.0.1:9050'},
                    args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
                )
                self._ready.set()   # signal: browser is up, callers may proceed
                logging.info('[PW] Chromium browser started.')

                while True:
                    item = self._q.get()
                    if item is self._SENTINEL:
                        break
                    
                    url, result, event, proxy = item
                        
                    context = None
                    try:
                        effective_proxy = proxy if proxy is not None else config.get_isolated_pw_proxy()
                        context = browser.new_context(
                            proxy=effective_proxy,  # type: ignore[arg-type]
                            java_script_enabled=True,
                            ignore_https_errors=True,
                        )
                        page = context.new_page()
                        PWS().apply_stealth_sync(page)  # type: ignore[misc]
                        page.goto(url, wait_until='networkidle', timeout=45_000)
                        result['html'] = page.content()
                        logging.info(
                            '[PW] Rendered %d bytes from %s',
                            len(result['html']), url,
                        )
                    except Exception as exc:
                        result['error'] = exc
                        logging.error('[PW] Error rendering %s: %s', url, exc)
                    finally:
                        if context:
                            try:
                                context.close()
                            except Exception:
                                pass
                        event.set()  # unblock the waiting worker thread

                browser.close()
        except Exception as exc:
            self._error = exc
            self._ready.set()  # unblock __init__ on startup failure
            logging.error('[PW] Worker crashed: %s', exc)

    def fetch(self, url: str, proxy: Optional[dict] = None) -> Optional[str]:
        """Submit *url* for JS rendering and block until the result is ready.

        Called from spider worker threads.  Thread-safe: uses Queue + Event.
        Returns the rendered HTML string, or None on error.
        """
        result: dict = {}
        event = threading.Event()
        self._q.put((url, result, event, proxy))
        event.wait()  # release as soon as the PW thread sets it
        return result.get('html')   # None if an error was stored instead

    def shutdown(self):
        """Ask the worker thread to exit gracefully and wait for it."""
        self._q.put(self._SENTINEL)
        self.join(timeout=10)


class DarkWebMonitor:
    """Base class for crawling and monitoring .onion sites over Tor.

    Handles:
      - Per-thread HTTP sessions with Tor SOCKS5 proxy and stream isolation
      - Automatic Playwright fallback for JS-rendered pages
      - Link extraction (regex + BeautifulSoup) for recursive crawling
      - File download detection (.zip, .sql) to quarantine directory
      - Anti-bot evasion: auto-rotates Tor circuit on 403 Forbidden
    """
    
    def __init__(self):
        self._thread_local = threading.local()
        self.validator = OnionValidator(proxy_url=config.TOR_PROXY)

        # Ensure quarantine directory exists
        self.quarantine_dir = config.QUARANTINE_DIR
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

        self.link_regex = re.compile(config.ONION_V3_REGEX)

        # Playwright worker — lazily created the first time a JS shell is
        # detected.  None means not yet needed (or unavailable).
        self._pw_worker: Optional[_PlaywrightWorker] = None
        self._pw_init_lock = threading.Lock()

    def _create_session(self):
        session = requests.Session()
        proxy_url = config.get_isolated_tor_proxy()
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        session.headers.update(config.get_random_header())
        return session

    def _get_session(self):
        if not hasattr(self._thread_local, "session"):
            self._thread_local.session = self._create_session()
        return self._thread_local.session

    def fetch_page_js(self, url: str) -> Optional[str]:
        """Fetch a page via headless Chromium routed through Tor.

        Delegates to the _PlaywrightWorker daemon thread so all Playwright
        calls happen in the same OS thread (greenlet constraint).
        """
        if not _PLAYWRIGHT_AVAILABLE:
            logging.warning('[PW] playwright not installed — JS fallback skipped.')
            return None

        # Lazy-start the worker the first time it's needed
        with self._pw_init_lock:
            if self._pw_worker is None:
                try:
                    self._pw_worker = _PlaywrightWorker()
                except Exception as exc:
                    logging.error('[PW] Could not start worker: %s', exc)
                    return None

        logging.info('[PW] JS-rendering: %s', url)
        pw_proxy = config.get_isolated_pw_proxy()
        return self._pw_worker.fetch(url, proxy=pw_proxy)

    def __del__(self):
        """Shut down the Playwright worker on garbage collection."""
        try:
            if self._pw_worker:
                self._pw_worker.shutdown()
        except Exception:
            pass


    def extract_links(self, html_content: str, source_url: str) -> List[str]:
        """Finds new .onion links in the page content."""
        new_links = set()
        try:
            # Method 1: Regex scan (fast, finds links in text)
            # findall returns the captured group (the domain)
            domains = self.link_regex.findall(html_content)
            for domain in domains:
                new_links.add(f"http://{domain}")
                
            # Method 2: BeautifulSoup (structured, finds hrefs)
            # This is still useful for extracting domains from links that might be obscured
            soup = BeautifulSoup(html_content, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = str(a['href'])
                match = self.link_regex.search(href)
                if match:
                   # Extracted onion domain from link
                   onion_domain = match.group(1) 
                   new_links.add(f"http://{onion_domain}")

            # Remove self reference
            if source_url in new_links:
                new_links.remove(source_url)
                
        except Exception as e:
            logging.error("Error extracting links: %s", e)
            
        return list(new_links)

    def fetch_page(self, url: str) -> Optional[str]:
        """
        Attempts to fetch a .onion page. Handles file downloads for .zip/.sql.
        """
        try:
            session = self._get_session()
            session.headers.update(config.get_random_header()) # Rotate UA per request
            logging.info("[*] Attempting to fetch: %s", url)
            response = session.get(url, timeout=30)
            
            # Anti-Bot Evasion (403 Forbidden)
            if response.status_code == 403:
                logging.warning("[!] Hit 403 Forbidden on %s. Generating new isolated circuit...", url)
                # Rotate identity purely by creating a new session with new random SOCKS credentials
                self._thread_local.session = self._create_session()
                session = self._thread_local.session
                
                logging.info("[*] Retrying with new isolated circuit...")
                try:
                    response = session.get(url, timeout=30)
                except RequestException:
                     # If retry fails, just log and move on
                    pass

            if response.status_code == 200:
                # Check for interesting files
                content_type = response.headers.get('Content-Type', '')
                if 'application/zip' in content_type or 'application/sql' in content_type or url.endswith(('.zip', '.sql')):
                    filename = os.path.join(self.quarantine_dir, os.path.basename(url) or "download.file")
                    with open(filename, 'wb') as f:
                        f.write(response.content)
                    logging.info("[+] Downloaded extraction to %s", filename)
                    return None  # return None so we don't parse binary as text

                html = response.text

                # JS-rendering fallback: if the page looks like an empty shell,
                # re-fetch it with Playwright so JS has a chance to run.
                if config.PLAYWRIGHT_ENABLED and _is_js_rendered(html):
                    logging.info('[PW] JS shell detected on %s — switching to Playwright.', url)
                    js_html = self.fetch_page_js(url)
                    if js_html:
                        return js_html
                    logging.warning('[PW] Playwright fetch failed for %s, using raw HTML.', url)

                return html
            else:
                logging.warning("[!] Failed with status: %s", response.status_code)
                return None
                
        except RequestException as e:
            logging.error("[!] Connection error (common on Tor): %s", e)
            return None

class PersistentDarkWebMonitor(DarkWebMonitor):
    """Database-backed spider that scans seeds in parallel and persists results.

    Reads seed URLs and keywords from SQLite, scans them concurrently using
    a ThreadPoolExecutor, and saves matches back to the database.  Supports
    graceful shutdown via Ctrl+C or ``request_shutdown()``.
    """
    def __init__(self, db_path=config.DB_PATH, **kwargs):
        super().__init__(**kwargs)
        self.db = DatabaseManager(db_path)
        self._shutdown = threading.Event()  # cooperative shutdown flag

    def request_shutdown(self):
        """Signal all workers to stop gracefully."""
        self._shutdown.set()

    def process_url(self, url: str, keywords: List[Tuple[str, str]]):
        """Worker function to process a single URL."""
        if self._shutdown.is_set():
            return  # bail out early if shutdown was requested

        try:
            html_content = self.fetch_page(url)
            
            if html_content:
                # Success
                self.db.update_seed_status(url, True)
                
                # 1. Check Keywords — build {keyword: context_snippet} dict
                found_matches = {}
                for kw, k_type in keywords:
                    if k_type == 'REGEX':
                        try:
                            m = re.search(kw, html_content, re.IGNORECASE)
                            if m:
                                ctx = _extract_context(html_content, m.start(), m.end())
                                found_matches[f"REGEX:{kw}"] = ctx
                        except re.error:
                            logging.error("Invalid regex: %s", kw)
                    else:
                        # Case-insensitive string match
                        lower_content = html_content.lower()
                        idx = lower_content.find(kw.lower())
                        if idx != -1:
                            ctx = _extract_context(html_content, idx, idx + len(kw))
                            found_matches[kw] = ctx

                if found_matches:
                    logging.info("[!!!] MATCH FOUND on %s: %s", url, found_matches)
                    self.db.save_match(url, found_matches)
                    
                # 2. Recursive Crawling: Extract and Add New Links
                new_links = self.extract_links(html_content, url)
                if new_links:
                    count = self.db.add_seeds(new_links)
                    if count > 0:
                        logging.info("[+] Discovered %d new unique seeds from %s", count, url)
            else:
                # Failure
                self.db.update_seed_status(url, False)
                
        except Exception as e:
            logging.error("Error processing %s: %s", url, e)
        finally:
            time.sleep(2)  # Per-worker cooldown; runs concurrently across all workers

    def run_automated_scan(self):
        """Main loop: fetches seeds from DB and scans in parallel.
        
        Supports graceful shutdown via Ctrl+C — in-flight requests finish,
        queued work is cancelled, and the method returns cleanly.
        """
        self._shutdown.clear()  # reset in case of re-use
        
        # 1. Fetch seeds from DB
        seeds = self.db.get_active_seeds()
        
        # 2. Fetch keywords from DB
        keywords = self.db.get_keywords()
        
        if not keywords:
            logging.warning("[-] No search keywords found in database! Please use keyword_manager.py to add some.")
            return

        if not seeds:
            logging.info("[-] No active seeds in database.")
            return

        logging.info("Starting scan on %d seeds looking for %d keywords with %d workers...", len(seeds), len(keywords), config.MAX_WORKERS)
        logging.info("Press Ctrl+C to stop gracefully.")
        
        # 3. Parallel Execution
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=config.MAX_WORKERS)
        future_to_url = {executor.submit(self.process_url, url, keywords): url for url in seeds}
        
        try:
            for future in concurrent.futures.as_completed(future_to_url):
                if self._shutdown.is_set():
                    break
                url = future_to_url[future]
                try:
                    future.result()
                except Exception as exc:
                    logging.error("%s generated an exception: %s", url, exc)
        except KeyboardInterrupt:
            logging.warning("\n[!] Ctrl+C received — shutting down gracefully...")
            self._shutdown.set()
            # Cancel any futures that haven't started yet
            for future in future_to_url:
                future.cancel()
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
            # Ensure the Playwright worker is always cleaned up
            if self._pw_worker:
                self._pw_worker.shutdown()
                self._pw_worker = None
        
        if self._shutdown.is_set():
            logging.info("Scan interrupted. Progress has been saved to the database.")
        else:
            logging.info("Scan complete.")

if __name__ == "__main__":
    if not start_tor_service():
        sys.exit(1)
        
    # Example Usage
    target_onions = [
        "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/",
    ]
    
    monitor = PersistentDarkWebMonitor()
    logging.info("Initializing Persistent Monitor...")
    
    # Pre-populate DB for testing if empty
    monitor.db.add_seeds(target_onions)
    
    # Run the scan (keywords now pulled from DB)
    monitor.run_automated_scan()
