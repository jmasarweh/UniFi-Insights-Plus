/**
 * Feature 1: Inject a "Insights Plus" tab into the UniFi Controller portal nav.
 * Clicking it embeds the Insights Plus app in the UniFi content area below the nav.
 *
 * Boots independently after shared config is available.
 * Runs in content script isolated world (has chrome.runtime access).
 */

;(async function bootstrap() {
  if (window.__uliTabInjectorStarted) return;
  window.__uliTabInjectorStarted = true;
  window.__uliTabInjectorBootstrap = bootstrap;

  if (!window.__uliUtils?.ensureConfig) return;
  const config = await window.__uliUtils.ensureConfig();
  if (!config) {
    window.__uliTabInjectorStarted = false;
    return;
  }

  const detectUniFiTheme = window.__uliUtils.detectTheme;

  const onRuntimeMessage = (msg, _sender, sendResponse) => {
    if (!msg || msg.type !== 'ULI_GET_THEME') return;
    sendResponse({ ok: true, theme: detectUniFiTheme() });
    return true;
  };
  chrome.runtime.onMessage.addListener(onRuntimeMessage);
  window.addEventListener('pagehide', () => {
    chrome.runtime.onMessage.removeListener(onRuntimeMessage);
  }, { once: true });
  chrome.storage.local.set({ unifiUiTheme: detectUniFiTheme() }).catch(() => {});

  if (!config.enableTabInjection) return;

  const logInsightUrl = config.baseUrl;
  if (!logInsightUrl) return;

  let logInsightOrigin;
  try {
    logInsightOrigin = new URL(logInsightUrl).origin;
  } catch (e) {
    console.error('Invalid Insights Plus URL:', logInsightUrl, e);
    return;
  }
  // Inline SVG data URIs — eliminates web_accessible_resources and prevents
  // external sites from fingerprinting the extension via icon probing.
  const _iconSvg = (color, textColor) => `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 116" fill="none"><path d="M 29 68 C 22 62,16 53,16 41 A 34 34 0 1 1 84 41 C 84 53,78 62,71 68 Z" fill="${color}" fill-opacity="0.12"/><path d="M 29 68 C 22 62,16 53,16 41 A 34 34 0 1 1 84 41 C 84 53,78 62,71 68" stroke="${color}" stroke-width="5.2" stroke-linecap="round" fill="none"/><path d="M 28 34 A 18 18 0 0 1 44 22" stroke="${color}" stroke-width="4.8" stroke-linecap="round" fill="none" opacity="0.7"/><line x1="28" y1="75" x2="72" y2="75" stroke="${color}" stroke-width="5.2" stroke-linecap="round"/><line x1="36" y1="84" x2="64" y2="84" stroke="${color}" stroke-width="5.2" stroke-linecap="round"/><text x="50" y="110" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,sans-serif" font-weight="800" font-size="19" letter-spacing="0.16em" fill="${textColor || color}">PLUS</text></svg>`)}`;
  const iconUrlGreyLight = _iconSvg('#6b7280');
  const iconUrlGreyDark = _iconSvg('#4b5563');
  const iconUrlBlue = _iconSvg('#14b8a6', '#0d9488');

  /** Return the correct inactive icon URL for the current theme. */
  function inactiveIconUrl() {
    return lastTheme === 'dark' ? iconUrlGreyDark : iconUrlGreyLight;
  }

  let isActive = false;
  let iframeContainer = null;
  let iframe = null;
  let uliTab = null;
  let navRoot = null;        // authoritative nav container (set once at injection)
  let capturedActiveTab = null; // the UniFi tab that was active when we activated
  let themeObs = null;
  let lastUrl = location.href;
  let lastTheme = detectUniFiTheme();
  let iframeLoaded = false;       // true after iframe fires its first 'load' event
  let pendingNavigate = null;     // queued hash for delivery after iframe loads

  // Wait indefinitely for the tab container to render — it may not exist
  // until after login completes (SPA route change, no full reload).
  const tabContainer = await waitForTabContainer();
  if (!tabContainer) return; // only if page is unloading

  injectTab(tabContainer);

  // Re-inject if SPA re-renders the header
  const headerObs = new MutationObserver(() => {
    // Use navRoot if still connected, else fall back to fresh query
    const container = (navRoot && navRoot.isConnected) ? navRoot : findTabContainer();
    if (container && !container.querySelector('[data-uli-tab]')) {
      injectTab(container);
    }
  });
  headerObs.observe(document.body, { childList: true, subtree: true });

  // Watch for UniFi theme changes and re-sync tab styling + iframe theme
  themeObs = window.__uliUtils.onThemeChange(onThemeChanged);

  // Route-change safety net: if URL changes while embed is active, force deactivate.
  // Covers pushState, replaceState, popstate, and hashchange.
  const origPushState = history.pushState;
  const origReplaceState = history.replaceState;
  history.pushState = function (...args) {
    origPushState.apply(this, args);
    onPossibleRouteChange();
  };
  history.replaceState = function (...args) {
    origReplaceState.apply(this, args);
    onPossibleRouteChange();
  };
  window.addEventListener('popstate', onPossibleRouteChange);
  window.addEventListener('hashchange', onPossibleRouteChange);

  function onPossibleRouteChange() {
    if (!isActive) { lastUrl = location.href; return; }
    if (location.href !== lastUrl) {
      deactivateEmbed();
    }
    lastUrl = location.href;
  }

  const teardown = () => {
    headerObs.disconnect();
    if (themeObs) {
      themeObs.disconnect();
      themeObs = null;
    }
    history.pushState = origPushState;
    history.replaceState = origReplaceState;
    window.removeEventListener('popstate', onPossibleRouteChange);
    window.removeEventListener('hashchange', onPossibleRouteChange);
    document.removeEventListener('keydown', onEscKey);
    window.removeEventListener('uli-navigate', onUliNavigate);
    window.__uliTabInjectorStarted = false;
  };
  window.addEventListener('pagehide', teardown, { once: true });

  function waitForTabContainer() {
    return new Promise((resolve) => {
      const found = findTabContainer();
      if (found) { resolve(found); return; }
      let settled = false;
      const obs = new MutationObserver(() => {
        const el = findTabContainer();
        if (el && !settled) { settled = true; obs.disconnect(); resolve(el); }
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      // Clean up on pagehide (page discard or bfcache entry) if the container never appeared
      window.addEventListener('pagehide', () => {
        if (!settled) { settled = true; obs.disconnect(); resolve(null); }
      }, { once: true });
    });
  }

  function findTabContainer() {
    const candidates = document.querySelectorAll(
      'header[class*="unifi-portal"] div[class*="unifi-portal"]'
    );
    for (const el of candidates) {
      if (el.querySelectorAll(':scope > a').length >= 1) return el;
    }
    return null;
  }

  /**
   * Find the best tab to clone — an inactive tab with text (e.g. "Protect").
   */
  function findInactiveTab(container) {
    const links = container.querySelectorAll(':scope > a');
    let best = null;
    for (const link of links) {
      const text = link.textContent.trim();
      if (!text) continue;
      if (link.hasAttribute('data-uli-tab')) continue;
      if (!isTabActive(link)) return link;
      if (!best) best = link;
    }
    return best;
  }

  /**
   * Find the currently active UniFi tab using explicit ARIA/class signals first,
   * then fall back to URL matching.
   */
  function findActiveUniFiTab(container) {
    const links = container.querySelectorAll(':scope > a');
    let urlMatch = null;
    let fallback = null;

    for (const link of links) {
      if (link.hasAttribute('data-uli-tab')) continue;
      if (!fallback) fallback = link;

      // Prefer explicit active signals (aria-current, aria-selected, active class)
      if (isTabActive(link)) return link;

      // URL match as secondary signal — resolve to absolute path to avoid
      // false positives with short hrefs like "/" or "/network"
      const hrefAttr = link.getAttribute('href') || link.href || '';
      if (!urlMatch && hrefAttr && hrefAttr.length > 1) {
        try {
          const resolved = new URL(hrefAttr, location.href).pathname;
          if (location.pathname.startsWith(resolved)) {
            urlMatch = link;
          }
        } catch { /* skip malformed href */ }
      }
    }
    return urlMatch || fallback;
  }

  /**
   * Check if a tab element has explicit active indicators from UniFi.
   */
  function isTabActive(link) {
    if (link.getAttribute('aria-current') === 'page' ||
        link.getAttribute('aria-current') === 'true') return true;
    if (link.getAttribute('aria-selected') === 'true') return true;
    const cls = link.className || '';
    if (/\bactive\b/i.test(cls) || /\bselected\b/i.test(cls)) return true;
    return false;
  }

  function injectTab(container) {
    if (container.querySelector('[data-uli-tab]')) return;

    const templateTab = findInactiveTab(container);
    if (!templateTab) return;

    const tab = templateTab.cloneNode(true);
    tab.setAttribute('data-uli-tab', 'true');
    tab.removeAttribute('href');
    tab.setAttribute('role', 'button');
    tab.style.cursor = 'pointer';

    // Replace icon SVG with our app icon, keep the title div
    const iconContainer = tab.querySelector('div');
    if (iconContainer) {
      // Remove the SVG but keep the title div
      const svg = iconContainer.querySelector('svg');
      if (svg) svg.remove();

      const img = document.createElement('img');
      img.src = inactiveIconUrl();
      img.width = 22;
      img.height = 22;
      img.alt = 'Insights Plus';
      img.style.cssText = 'border-radius:4px;margin:3px 5px 3px 3px';
      iconContainer.insertBefore(img, iconContainer.firstChild);

      // Update the title text
      const titleDiv = iconContainer.querySelector('.title');
      if (titleDiv) {
        titleDiv.textContent = 'Insights Plus';
      } else {
        // Create title div if it doesn't exist
        const title = document.createElement('div');
        title.className = 'title';
        title.textContent = 'Insights Plus';
        iconContainer.appendChild(title);
      }
    }

    tab.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (isActive) {
        deactivateEmbed();
      } else {
        activateEmbed();
      }
    });

    container.appendChild(tab);
    uliTab = tab;
    navRoot = container; // authoritative reference — never re-query for click scope

    // Attach deactivation listeners to each real UniFi tab
    attachDeactivationListeners(container);

    // If we're currently active, apply active styling to the fresh tab
    if (isActive) syncTabStyling();
  }

  function attachDeactivationListeners(container) {
    const links = container.querySelectorAll(':scope > a');
    for (const link of links) {
      if (link.hasAttribute('data-uli-tab')) continue;
      if (link.hasAttribute('data-uli-deactivate')) continue;
      link.setAttribute('data-uli-deactivate', 'true');
      link.addEventListener('click', () => {
        if (isActive) deactivateEmbed();
      }, true);
    }
  }

  // ── Activate / Deactivate ────────────────────────────────────────────────

  function activateEmbed() {
    if (isActive) return;

    // Capture the currently-active UniFi tab BEFORE we modify anything.
    if (navRoot && navRoot.isConnected) {
      capturedActiveTab = findActiveUniFiTab(navRoot);
    }

    // Use fixed overlay so we never touch <main> or hold stale references.
    // Re-create if the SPA removed it from the DOM during app navigation.
    if (!iframeContainer || !iframeContainer.isConnected) {
      iframeContainer = createIframeContainer();
      document.body.appendChild(iframeContainer);
    }

    iframeContainer.style.display = 'block';
    syncTabStyling();
    isActive = true;
    lastUrl = location.href;
  }

  function deactivateEmbed() {
    if (!isActive) return;
    if (iframeContainer) iframeContainer.style.display = 'none';
    restoreTabStyling();
    capturedActiveTab = null;
    isActive = false;
  }

  // ── Tab styling ─────────────────────────────────────────────────────────
  //
  // UniFi drives active tab styling via aria-current="page" matched by
  // CSS-in-JS selectors. Same CSS classes on all tabs — only the ARIA
  // attribute differs. We manipulate aria-current directly instead of
  // fighting CSS specificity with inline style overrides.

  function syncTabStyling() {
    if (!uliTab) return;

    // Remove active indicator from the real UniFi tab
    if (capturedActiveTab && capturedActiveTab.isConnected) {
      capturedActiveTab.removeAttribute('aria-current');
    }

    // Make our tab look active
    uliTab.setAttribute('aria-current', 'page');

    // Swap icon to active blue
    const img = uliTab.querySelector('img');
    if (img) img.src = iconUrlBlue;
  }

  function restoreTabStyling() {
    // Restore the real UniFi tab's active state (only if still connected —
    // after SPA navigation React may have replaced the element)
    if (capturedActiveTab && capturedActiveTab.isConnected) {
      capturedActiveTab.setAttribute('aria-current', 'page');
    }

    // Remove active state from our tab and reset icon to inactive grey
    if (uliTab && uliTab.isConnected) {
      uliTab.removeAttribute('aria-current');
      const img = uliTab.querySelector('img');
      if (img) img.src = inactiveIconUrl();
    }

    // Safety: ensure no lingering aria-current on our tab after React re-renders
    const freshUli = document.querySelector('[data-uli-tab]');
    if (freshUli && freshUli !== uliTab) {
      freshUli.removeAttribute('aria-current');
      const img = freshUli.querySelector('img');
      if (img) img.src = inactiveIconUrl();
      uliTab = freshUli;
    }
  }

  function onThemeChanged(theme) {
    lastTheme = theme;
    if (uliTab) {
      // UniFi re-rendered all tabs with new theme CSS classes.
      // Update our tab's className to match the current inactive tabs
      // so it looks correct both now and after deactivation.
      const container = uliTab.parentElement;
      if (container) {
        const inactiveTab = findInactiveTab(container);
        if (inactiveTab) {
          uliTab.className = inactiveTab.className;
          uliTab.setAttribute('data-uli-tab', 'true');
          uliTab.removeAttribute('href');
          uliTab.style.cursor = 'pointer';
        }
      }

      // Update icon for new theme and re-apply styling
      if (isActive) {
        restoreTabStyling();
        syncTabStyling();
      } else {
        const img = uliTab.querySelector('img');
        if (img) img.src = inactiveIconUrl();
      }
    }

    // Tell the iframe to switch theme
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'uli-theme', theme }, logInsightOrigin);
    }
    chrome.storage.local.set({ unifiUiTheme: theme }).catch(() => {});
  }

  // ── Iframe ──────────────────────────────────────────────────────────────

  function createIframeContainer() {
    // Use fixed positioning to overlay the content area.
    // This avoids hiding/showing <main> and holding stale DOM references.
    const header = document.querySelector('header[class*="unifi-portal"]');
    const headerH = header ? header.getBoundingClientRect().height : 48;

    const container = document.createElement('div');
    container.id = 'uli-embed';
    container.style.cssText = `display:none;position:fixed;top:${headerH}px;left:0;right:0;bottom:0;z-index:1000;`;

    const theme = detectUniFiTheme();
    iframe = document.createElement('iframe');
    iframeLoaded = false;
    const iframeSrc = new URL(logInsightUrl);
    iframeSrc.searchParams.set('theme', theme);
    iframe.src = iframeSrc.href;
    iframe.sandbox = 'allow-scripts allow-same-origin allow-forms allow-popups';
    iframe.style.cssText = 'width:100%;height:100%;border:none;';

    iframe.addEventListener('load', () => {
      iframeLoaded = true;
      if (pendingNavigate && iframe.contentWindow) {
        iframe.contentWindow.postMessage({ type: 'uli-navigate', hash: pendingNavigate }, logInsightOrigin);
        pendingNavigate = null;
      }
    });

    container.appendChild(iframe);
    return container;
  }

  // ESC to deactivate (ignore when focus is on interactive elements)
  const onEscKey = (e) => {
    if (e.key === 'Escape' && isActive) {
      const el = e.target || document.activeElement;
      if (el && el.matches('input, textarea, select, button, [contenteditable="true"]')) return;
      deactivateEmbed();
    }
  };
  document.addEventListener('keydown', onEscKey);

  // Deactivate when user clicks another UniFi tab.
  // Listeners are attached directly to each tab <a> in attachDeactivationListeners()
  // called from injectTab(). This is more reliable than a document-level handler
  // because content script capture listeners on document can miss events in some
  // browser/extension configurations.

  // Listen for navigation requests from flow-enricher / panel-enricher clicks
  const onUliNavigate = (e) => {
    const { ip, range, dir } = e.detail || {};
    if (!ip) return;

    let hash = '#logs?ip=' + encodeURIComponent(ip);
    if (range) hash += '&range=' + encodeURIComponent(range);
    if (dir === 'src' || dir === 'dst') hash += '&dir=' + dir;

    // Activate embed if hidden
    if (!isActive) activateEmbed();

    if (iframe && iframe.contentWindow) {
      if (iframeLoaded) {
        // Iframe already loaded — deliver immediately
        iframe.contentWindow.postMessage({ type: 'uli-navigate', hash }, logInsightOrigin);
      } else {
        // Iframe still loading — queue for delivery after 'load' event
        pendingNavigate = hash;
      }
    }
  };
  window.addEventListener('uli-navigate', onUliNavigate);
})();
// BFCache restore: pagehide tears down observers but content scripts are not
// re-injected. Re-bootstrap when the page is restored from cache.
window.addEventListener('pageshow', (e) => {
  if (e.persisted && !window.__uliTabInjectorStarted) {
    window.__uliTabInjectorBootstrap?.();
  }
});
