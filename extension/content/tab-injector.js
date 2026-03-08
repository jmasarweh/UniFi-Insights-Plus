/**
 * Feature 1: Inject a "Log Insight" tab into the UniFi Controller portal nav.
 * Clicking it embeds the Log Insight app in the UniFi content area below the nav.
 *
 * Activated by 'uli-ready' event from controller-detector.js.
 * Runs in content script isolated world (has chrome.runtime access).
 */

window.addEventListener('uli-ready', async function () {
  const config = window.__uliConfig;
  if (!config || !config.enableTabInjection) return;

  const logInsightUrl = config.baseUrl;
  if (!logInsightUrl) return;

  let logInsightOrigin;
  try {
    logInsightOrigin = new URL(logInsightUrl).origin;
  } catch (e) {
    console.error('Invalid Log Insight URL:', logInsightUrl, e);
    return;
  }
  const iconUrl = chrome.runtime.getURL('icons/icon-32.png');

  let isActive = false;
  let iframeContainer = null;
  let iframe = null;
  let mainContent = null;
  let uliTab = null;

  // Wait for the tab container to render
  const tabContainer = await waitForTabContainer(15000);
  if (!tabContainer) return;

  injectTab(tabContainer);

  // Re-inject if SPA re-renders the header
  const headerObs = new MutationObserver(() => {
    const container = findTabContainer();
    if (container && !container.querySelector('[data-uli-tab]')) {
      injectTab(container);
    }
  });
  headerObs.observe(document.body, { childList: true, subtree: true });

  // Watch for UniFi theme changes and re-sync tab styling + iframe theme
  observeThemeChanges();

  function waitForTabContainer(timeout) {
    return new Promise((resolve) => {
      const found = findTabContainer();
      if (found) { resolve(found); return; }
      const obs = new MutationObserver(() => {
        const el = findTabContainer();
        if (el) { obs.disconnect(); resolve(el); }
      });
      obs.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => { obs.disconnect(); resolve(null); }, timeout);
    });
  }

  function findTabContainer() {
    const candidates = document.querySelectorAll(
      'header[class*="unifi-portal"] div[class*="unifi-portal"]'
    );
    for (const el of candidates) {
      if (el.querySelectorAll(':scope > a').length >= 2) return el;
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
      if (!location.href.includes(link.href)) return link;
      if (!best) best = link;
    }
    return best;
  }

  /**
   * Find the currently active UniFi tab (the one matching the current URL).
   */
  function findActiveUniFiTab(container) {
    const links = container.querySelectorAll(':scope > a');
    for (const link of links) {
      if (link.hasAttribute('data-uli-tab')) continue;
      if (link.href && location.href.includes(link.getAttribute('href'))) return link;
    }
    return null;
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
      img.src = iconUrl;
      img.width = 24;
      img.height = 24;
      img.alt = 'Log Insight';
      img.style.borderRadius = '4px';
      iconContainer.insertBefore(img, iconContainer.firstChild);

      // Update the title text
      const titleDiv = iconContainer.querySelector('.title');
      if (titleDiv) {
        titleDiv.textContent = 'Log Insight';
      } else {
        // Create title div if it doesn't exist
        const title = document.createElement('div');
        title.className = 'title';
        title.textContent = 'Log Insight';
        iconContainer.appendChild(title);
      }
    }

    tab.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      toggleEmbed();
    });

    container.appendChild(tab);
    uliTab = tab;

    // If we're currently active, apply active styling to the fresh tab
    if (isActive) syncTabStyling();
  }

  // ── Toggle ──────────────────────────────────────────────────────────────

  function toggleEmbed() {
    if (isActive) {
      if (iframeContainer) iframeContainer.style.display = 'none';
      if (mainContent) mainContent.style.display = '';
      restoreTabStyling();
      isActive = false;
      return;
    }

    mainContent = document.querySelector('main');
    if (!mainContent) return;

    if (!iframeContainer) {
      iframeContainer = createIframeContainer();
      mainContent.parentElement.insertBefore(iframeContainer, mainContent.nextSibling);
    }

    mainContent.style.display = 'none';
    iframeContainer.style.display = 'block';
    syncTabStyling();
    isActive = true;
  }

  // ── Tab styling ─────────────────────────────────────────────────────────
  //
  // UniFi uses identical CSS classes for all tabs — active vs inactive is
  // determined by internal CSS selectors (URL match), not class differences.
  // We must override with inline styles, reading live computed values from
  // the real active/inactive tabs.

  let dimmedTab = null;

  function syncTabStyling() {
    if (!uliTab) return;
    const container = uliTab.parentElement;
    if (!container) return;

    restoreTabStyling();

    const activeTab = findActiveUniFiTab(container);
    const inactiveTab = findInactiveTab(container);
    if (!activeTab) return;

    // Read live computed styles before changing anything
    const activeCs = getComputedStyle(activeTab);
    const inactiveCs = inactiveTab ? getComputedStyle(inactiveTab) : null;
    const activeColor = activeCs.color;
    const activeBg = activeCs.backgroundColor;
    const inactiveColor = inactiveCs ? inactiveCs.color : null;
    const inactiveBg = inactiveCs ? inactiveCs.backgroundColor : null;

    // Make the real active tab look inactive
    if (inactiveColor) {
      activeTab.style.setProperty('color', inactiveColor, 'important');
      activeTab.style.setProperty('background-color', inactiveBg, 'important');
      dimmedTab = activeTab;
    }

    // Make our tab look active
    uliTab.style.setProperty('color', activeColor, 'important');
    uliTab.style.setProperty('background-color', activeBg, 'important');
  }

  function restoreTabStyling() {
    // Restore dimmed UniFi tab
    if (dimmedTab && dimmedTab.isConnected) {
      dimmedTab.style.removeProperty('color');
      dimmedTab.style.removeProperty('background-color');
    }
    dimmedTab = null;

    // Restore our tab
    if (uliTab && uliTab.isConnected) {
      uliTab.style.removeProperty('color');
      uliTab.style.removeProperty('background-color');
    }
  }

  // ── Theme detection ─────────────────────────────────────────────────────

  function detectUniFiTheme() {
    // UniFi uses a dark header bg in dark mode, light in light mode
    const header = document.querySelector('header[class*="unifi-portal"]');
    if (!header) return 'dark';
    const bg = getComputedStyle(header).backgroundColor;
    return isColorDark(bg) ? 'dark' : 'light';
  }

  function isColorDark(color) {
    // Parse rgb(r, g, b) or rgba(r, g, b, a)
    const m = color.match(/(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/);
    if (!m) return true; // default to dark
    const luminance = (0.299 * +m[1] + 0.587 * +m[2] + 0.114 * +m[3]);
    return luminance < 128;
  }

  let lastTheme = detectUniFiTheme();

  function observeThemeChanges() {
    // UniFi toggles themes by re-rendering the entire React tree with new
    // CSS-in-JS class names — no attribute changes on html/body.  We watch
    // the header for any child/attribute mutations and re-check the computed
    // background color to detect the switch.
    let debounce = null;
    const check = () => {
      const current = detectUniFiTheme();
      if (current !== lastTheme) {
        lastTheme = current;
        onThemeChanged(current);
      }
    };
    const themeObs = new MutationObserver(() => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(check, 200);
    });
    const header = document.querySelector('header[class*="unifi-portal"]');
    if (header) {
      themeObs.observe(header, { childList: true, subtree: true, attributes: true });
    }
    // Fallback: also watch body for large re-renders (SPA navigation)
    themeObs.observe(document.body, { childList: true, subtree: false });
  }

  function onThemeChanged(theme) {
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

      // Re-apply active inline styles if currently active
      if (isActive) {
        restoreTabStyling();
        syncTabStyling();
      }
    }

    // Tell the iframe to switch theme
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'uli-theme', theme }, logInsightOrigin);
    }
  }

  // ── Iframe ──────────────────────────────────────────────────────────────

  function createIframeContainer() {
    const container = document.createElement('div');
    container.id = 'uli-embed';
    container.style.cssText = 'display:none;position:relative;width:100%;height:calc(100vh - 50px);overflow:hidden;';

    const theme = detectUniFiTheme();
    iframe = document.createElement('iframe');
    iframe.src = logInsightUrl + '?theme=' + theme;
    iframe.sandbox = 'allow-scripts allow-same-origin allow-forms allow-popups';
    iframe.style.cssText = 'width:100%;height:100%;border:none;';

    container.appendChild(iframe);
    return container;
  }

  // ESC to deactivate (ignore when focus is on interactive elements)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && isActive) {
      const el = e.target || document.activeElement;
      if (el && el.matches('input, textarea, select, button, [contenteditable="true"]')) return;
      toggleEmbed();
    }
  });

  // Deactivate when user clicks another UniFi tab
  document.addEventListener('click', (e) => {
    if (!isActive) return;
    const clickedTab = e.target.closest('a');
    if (!clickedTab || clickedTab.hasAttribute('data-uli-tab')) return;
    const container = findTabContainer();
    if (container && container.contains(clickedTab)) {
      toggleEmbed();
    }
  }, true);

  // Listen for navigation requests from flow-enricher (pill/dot clicks)
  window.addEventListener('uli-navigate', (e) => {
    const { ip } = e.detail || {};
    if (!ip) return;

    // Activate the embed if not already active
    if (!isActive) toggleEmbed();

    // Navigate the iframe to logs filtered by IP
    if (iframe && iframe.contentWindow) {
      iframe.contentWindow.postMessage({ type: 'uli-navigate', hash: '#logs?ip=' + encodeURIComponent(ip) }, logInsightOrigin);
    }
  });
});
