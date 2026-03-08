(() => {
  function toOriginPattern(url) {
    try {
      const u = new URL(url);
      const hostPort = u.port ? `${u.hostname}:${u.port}` : u.hostname;
      return `${u.protocol}//${hostPort}/*`;
    } catch {
      return null;
    }
  }

  globalThis.ULI_URL_UTILS = Object.freeze({
    toOriginPattern,
  });
})();
