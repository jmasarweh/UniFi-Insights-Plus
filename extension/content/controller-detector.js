/**
 * Content script entry point — injected on the UniFi Controller page.
 * Detects the UniFi portal header, fetches extension config, then
 * dispatches a 'uli-ready' event so tab-injector.js and flow-enricher.js
 * can initialize.
 *
 * All three files are registered as content scripts in the same scope.
 * They share the content script isolated world (chrome.runtime access).
 * This file MUST be listed first in the registerContentScripts js array.
 */

(async function () {
  // Guard against duplicate injection (SPA re-navigation)
  if (document.getElementById('uli-detector-ran')) return;
  const guard = document.createElement('div');
  guard.id = 'uli-detector-ran';
  guard.style.display = 'none';
  document.documentElement.appendChild(guard);

  // Wait indefinitely for the SPA to render the portal header.
  // The header may not exist yet on the login page — it appears only after
  // authentication completes (SPA route change, no full reload).
  // The observer is cleaned up on pagehide or once the header is found.
  const header = await waitForElement('header[class*="unifi-portal"]');
  if (!header) return; // only if page is unloading

  if (!window.__uliUtils?.ensureConfig) return;
  const config = await window.__uliUtils.ensureConfig();
  if (!config) return;

  // Signal that detection is complete — other scripts are listening
  window.__uliReady = true;
  window.dispatchEvent(new CustomEvent('uli-ready'));
})();

/**
 * Wait for an element matching `selector` to appear in the DOM.
 * Watches indefinitely via MutationObserver until found or the page fires
 * pagehide (which occurs both when the page is discarded/unloaded and when
 * it enters bfcache). Returns null in either case.
 */
function waitForElement(selector) {
  return new Promise((resolve) => {
    const el = document.querySelector(selector);
    if (el) { resolve(el); return; }

    let settled = false;
    const observer = new MutationObserver(() => {
      const found = document.querySelector(selector);
      if (found && !settled) { settled = true; observer.disconnect(); resolve(found); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });

    // Clean up on pagehide (page discard or bfcache entry) if the element never appeared
    window.addEventListener('pagehide', () => {
      if (!settled) { settled = true; observer.disconnect(); resolve(null); }
    }, { once: true });
  });
}
