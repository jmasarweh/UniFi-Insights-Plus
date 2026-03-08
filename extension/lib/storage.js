/**
 * Wrapper around chrome.storage for extension settings.
 * Uses chrome.storage.sync for settings (synced across devices)
 * and chrome.storage.local for cache data.
 */

const DEFAULTS = {
  logInsightUrl: '',
  controllerUrl: '',
  enableTabInjection: true,
  enableFlowEnrichment: true,
  configured: false,
};

export async function getSettings() {
  try {
    return await chrome.storage.sync.get(DEFAULTS);
  } catch (err) {
    console.error('getSettings failed:', err);
    return { ...DEFAULTS };
  }
}

export async function saveSettings(settings) {
  try {
    await chrome.storage.sync.set(settings);
    return true;
  } catch (err) {
    console.error('saveSettings failed:', err);
    return false;
  }
}

export async function setCache(key, value) {
  try {
    await chrome.storage.local.set({ [key]: value });
  } catch (err) {
    console.error('setCache failed:', err);
  }
}
