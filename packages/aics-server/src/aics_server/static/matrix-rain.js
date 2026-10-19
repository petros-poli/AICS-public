/* wesupport-ai.com (WeSupport-AI, an AICS instance): dependency-free atmosphere and clipboard UI.
 * toggleMatrixRain() toggles; toggleMatrixRain(boolean) sets the preference.
 * Reduced motion always takes precedence. The return value is effective enablement.
 * Copy: data-copy-target="#id" (CSS selector or bare ID), data-copy-text="…",
 * or .copy-btn beside a pre/code/.curl-snippet in a shared container.
 * Optional: [data-copy-label] inside a button; [data-matrix-rain-toggle] controls.
 */
(() => {
  'use strict';

  const instanceKey = '__weSupportMatrixRain';
  if (window[instanceKey]) return;
  window[instanceKey] = true;

  const preferenceKey = 'aics:matrix-rain';
  const frameInterval = 1000 / 30;
  const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const glyphSets = [
    Array.from('アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン'),
    Array.from('0123456789ABCDEF'),
    Array.from('did:key:z6MkEd25519ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'),
    Array.from('01⊕∑⋈◇⟨⟩├┤┬┴│'),
  ];
  let enabled = true;
  let canvas = null;
  let context = null;
  let frame = null;
  let lastFrame = 0;
  let lastDraw = 0;
  let lastMutation = 0;
  let resizeTimer = null;
  let width = 0;
  let height = 0;
  let fontSize = 14;
  let streams = [];
  let pageActive = true;
  let liveRegion = null;
  let announceTimer = null;
  const feedback = new WeakMap();
  const pendingCopies = new WeakSet();

  try { enabled = window.localStorage.getItem(preferenceKey) !== 'off'; } catch { /* Storage can be unavailable. */ }

  function effectiveEnabled() { return enabled && !motionQuery.matches; }

  function randomGlyph() {
    const set = glyphSets[Math.floor(Math.random() * glyphSets.length)];
    return set[Math.floor(Math.random() * set.length)];
  }

  function makeStream(index, spacing) {
    const length = 9 + Math.floor(Math.random() * 15);
    return {
      x: index * spacing + spacing / 2,
      y: Math.random() * (height + length * 20),
      speed: 22 + Math.random() * 34,
      brightness: 0.3 + Math.random() * 0.45,
      glyphs: Array.from({ length }, randomGlyph),
    };
  }

  function resize() {
    if (!canvas || !context) return;
    width = Math.max(1, document.documentElement.clientWidth || window.innerWidth);
    height = Math.max(1, window.innerHeight || document.documentElement.clientHeight);
    // Bound backing-store memory on large / Retina displays without losing crisp text.
    const ratio = Math.min(window.devicePixelRatio || 1, 2, Math.sqrt(6000000 / (width * height)));
    canvas.width = Math.max(1, Math.round(width * ratio));
    canvas.height = Math.max(1, Math.round(height * ratio));
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    fontSize = width < 600 ? 13 : 14;
    context.font = `${fontSize}px "SFMono-Regular", Consolas, "Noto Sans Mono", monospace`;
    context.textAlign = 'center';
    context.textBaseline = 'top';
    const spacing = Math.max(27, width / 120);
    streams = Array.from({ length: Math.ceil(width / spacing) }, (_, index) => makeStream(index, spacing));
    lastFrame = 0;
    lastDraw = 0;
    lastMutation = 0;
  }

  function draw(now, elapsed) {
    context.clearRect(0, 0, width, height);
    const mutate = now - lastMutation > 180;
    if (mutate) lastMutation = now;
    for (const stream of streams) {
      stream.y += stream.speed * elapsed;
      if (stream.y - stream.glyphs.length * 20 > height) {
        stream.y = -Math.random() * height * 0.4;
      }
      if (mutate) stream.glyphs[Math.floor(Math.random() * stream.glyphs.length)] = randomGlyph();
      for (let index = 0; index < stream.glyphs.length; index += 1) {
        const y = Math.round(stream.y - index * 20);
        if (y < -fontSize || y > height) continue;
        context.globalAlpha = stream.brightness * Math.pow(1 - index / stream.glyphs.length, 1.7);
        context.fillStyle = index === 0 ? '#a3ffd0' : index < 3 ? '#00ff66' : '#00cc52';
        context.fillText(stream.glyphs[index], Math.round(stream.x), y);
      }
    }
    context.globalAlpha = 1;
  }

  function tick(now) {
    if (!effectiveEnabled() || document.hidden || !pageActive) {
      stop();
      return;
    }
    if (!lastFrame) lastFrame = now - frameInterval;
    const delta = now - lastFrame;
    if (delta >= frameInterval) {
      draw(now, Math.min(lastDraw ? now - lastDraw : frameInterval, 100) / 1000);
      lastDraw = now;
      lastFrame = now - (delta % frameInterval);
    }
    frame = window.requestAnimationFrame(tick);
  }

  function stop() {
    if (frame !== null) window.cancelAnimationFrame(frame);
    frame = null;
    lastFrame = 0;
    lastDraw = 0;
    if (context) context.clearRect(0, 0, width, height);
    if (canvas) canvas.hidden = true;
  }

  function sync() {
    const active = effectiveEnabled();
    document.querySelectorAll('[data-matrix-rain-toggle]').forEach(control => {
      control.setAttribute('aria-pressed', String(active));
    });
    if (!context || !active || document.hidden || !pageActive) {
      stop();
      return;
    }
    canvas.hidden = false;
    if (frame === null) frame = window.requestAnimationFrame(tick);
  }

  window.toggleMatrixRain = function toggleMatrixRain(value) {
    enabled = typeof value === 'boolean' ? value : !enabled;
    try { window.localStorage.setItem(preferenceKey, enabled ? 'on' : 'off'); } catch { /* Optional persistence. */ }
    sync();
    return effectiveEnabled();
  };

  function announce(message) {
    if (!liveRegion) {
      liveRegion = document.createElement('span');
      liveRegion.className = 'sr-only';
      liveRegion.setAttribute('role', 'status');
      liveRegion.setAttribute('aria-live', 'polite');
      liveRegion.setAttribute('aria-atomic', 'true');
      // Feedback remains accessible even when this script is used without matrix.css.
      Object.assign(liveRegion.style, { position: 'fixed', width: '1px', height: '1px', overflow: 'hidden', clipPath: 'inset(50%)', whiteSpace: 'nowrap' });
      document.body.appendChild(liveRegion);
    }
    window.clearTimeout(announceTimer);
    liveRegion.textContent = '';
    announceTimer = window.setTimeout(() => { liveRegion.textContent = message; }, 30);
  }

  function findCopySource(control) {
    if (control.hasAttribute('data-copy-target')) {
      const selector = control.getAttribute('data-copy-target').trim();
      if (!selector) return null;
      const byId = document.getElementById(selector.startsWith('#') ? selector.slice(1) : selector);
      if (byId) return byId;
      try { return document.querySelector(selector); } catch { return null; }
    }
    const described = control.getAttribute('aria-controls');
    if (described) return document.getElementById(described);
    const enclosing = control.closest('pre, .curl-snippet');
    if (enclosing) return enclosing;
    const scope = control.closest('[data-copy-container], .agent-quickstart-box, .matrix-card, .matrix-panel, .merkle-root-bar');
    return (control.parentElement && control.parentElement.querySelector('.curl-snippet, pre, code'))
      || (scope && scope.querySelector('.curl-snippet, pre, code'));
  }

  function readCopyText(control) {
    if (control.hasAttribute('data-copy-text')) return control.getAttribute('data-copy-text');
    const source = findCopySource(control);
    if (!source) throw new Error('Copy source missing');
    if (source.matches('input, textarea, select')) return source.value;
    const clone = source.cloneNode(true);
    // Embedded toolbar labels must never leak into a command or identifier.
    clone.querySelectorAll('.copy-btn, [data-copy-target], [data-copy-ignore]').forEach(node => node.remove());
    return clone.textContent;
  }

  function fallbackCopy(text) {
    const previousFocus = document.activeElement;
    const selection = window.getSelection();
    const ranges = selection ? Array.from({ length: selection.rangeCount }, (_, i) => selection.getRangeAt(i).cloneRange()) : [];
    const inputSelection = previousFocus && /^(INPUT|TEXTAREA)$/.test(previousFocus.tagName)
      ? { start: previousFocus.selectionStart, end: previousFocus.selectionEnd, direction: previousFocus.selectionDirection }
      : null;
    const field = document.createElement('textarea');
    field.value = text;
    field.readOnly = true;
    field.tabIndex = -1;
    field.setAttribute('aria-label', 'Text to copy');
    Object.assign(field.style, { position: 'fixed', top: '0', left: '-9999px', opacity: '0', fontSize: '16px' });
    document.body.appendChild(field);
    try {
      field.focus({ preventScroll: true });
      field.select();
      if (!document.execCommand('copy')) throw new Error('Clipboard unavailable');
    } finally {
      field.remove();
      if (previousFocus && previousFocus.isConnected && typeof previousFocus.focus === 'function') {
        previousFocus.focus({ preventScroll: true });
        if (inputSelection && inputSelection.start !== null) {
          previousFocus.setSelectionRange(inputSelection.start, inputSelection.end, inputSelection.direction || 'none');
        }
      }
      if (selection) {
        selection.removeAllRanges();
        ranges.forEach(range => selection.addRange(range));
      }
    }
  }

  async function writeClipboard(text) {
    if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try { await navigator.clipboard.writeText(text); return; } catch { /* Try the user-gesture fallback. */ }
    }
    fallbackCopy(text);
  }

  function showFeedback(control, success) {
    let state = feedback.get(control);
    if (!state) {
      const label = control.querySelector('[data-copy-label]');
      const textNode = label ? null : Array.from(control.childNodes).find(node => node.nodeType === Node.TEXT_NODE && node.textContent.trim());
      state = {
        title: control.getAttribute('title'),
        ariaLabel: control.getAttribute('aria-label'),
        previousState: control.getAttribute('data-copy-state'),
        label,
        textNode,
        text: label ? label.textContent : textNode ? textNode.textContent : null,
        timer: null,
      };
      feedback.set(control, state);
    }
    window.clearTimeout(state.timer);
    const message = success ? 'Copied to clipboard' : 'Copy failed. Select the text and copy manually.';
    const shortLabel = success ? 'Copied' : 'Copy failed';
    control.setAttribute('data-copy-state', success ? 'copied' : 'error');
    control.setAttribute('title', message);
    control.setAttribute('aria-label', message);
    if (state.label) state.label.textContent = shortLabel;
    else if (state.textNode) state.textNode.textContent = ` ${shortLabel} `;
    announce(message);
    state.timer = window.setTimeout(() => {
      for (const [attribute, value] of [['title', state.title], ['aria-label', state.ariaLabel], ['data-copy-state', state.previousState]]) {
        if (value === null) control.removeAttribute(attribute);
        else control.setAttribute(attribute, value);
      }
      if (state.label) state.label.textContent = state.text;
      else if (state.textNode) state.textNode.textContent = state.text;
      feedback.delete(control);
    }, success ? 1800 : 3500);
  }

  function isDisabled(control) {
    return control.matches(':disabled, [disabled], [aria-disabled="true"]');
  }

  async function copy(control) {
    if (isDisabled(control) || pendingCopies.has(control)) return;
    pendingCopies.add(control);
    try {
      const text = readCopyText(control);
      if (text === null || text === '') throw new Error('Copy source empty');
      await writeClipboard(text);
      showFeedback(control, true);
    } catch {
      showFeedback(control, false);
    } finally {
      pendingCopies.delete(control);
    }
  }

  function init() {
    canvas = document.getElementById('matrix-rain-canvas');
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.id = 'matrix-rain-canvas';
      document.body.prepend(canvas);
    }
    if (canvas instanceof HTMLCanvasElement) {
      canvas.setAttribute('aria-hidden', 'true');
      canvas.setAttribute('role', 'presentation');
      canvas.tabIndex = -1;
      Object.assign(canvas.style, { position: 'fixed', inset: '0', width: '100%', height: '100%', opacity: '0.14', pointerEvents: 'none', zIndex: '-1' });
      if (window.getComputedStyle(document.body).isolation !== 'isolate') document.body.style.isolation = 'isolate';
      try { context = canvas.getContext('2d', { alpha: true }); } catch { /* Copy still works without Canvas. */ }
      resize();
    } else { canvas = null; }

    document.addEventListener('click', event => {
      const target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      const copyControl = target.closest('[data-copy-target], .copy-btn');
      if (copyControl) {
        event.preventDefault();
        void copy(copyControl);
        return;
      }
      const toggle = target.closest('[data-matrix-rain-toggle]');
      if (toggle) {
        event.preventDefault();
        if (!isDisabled(toggle)) window.toggleMatrixRain();
      }
    });
    // Custom role=button controls receive the same keyboard activation as buttons.
    document.addEventListener('keydown', event => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      const target = event.target instanceof Element ? event.target : null;
      if (!target || !target.matches('[role="button"][data-copy-target], [role="button"].copy-btn, [role="button"][data-matrix-rain-toggle]')) return;
      if (target.matches('button, input, textarea, select, a[href]') || target.isContentEditable) return;
      event.preventDefault();
      if (!event.repeat) target.click();
    });
    window.addEventListener('resize', () => {
      window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(() => { resize(); sync(); }, 150);
    }, { passive: true });
    document.addEventListener('visibilitychange', sync);
    window.addEventListener('pagehide', () => { pageActive = false; stop(); });
    window.addEventListener('pageshow', () => { pageActive = true; sync(); });
    window.addEventListener('storage', event => {
      if (event.key === preferenceKey || event.key === null) { enabled = event.newValue !== 'off'; sync(); }
    });
    if (typeof motionQuery.addEventListener === 'function') motionQuery.addEventListener('change', sync);
    else if (typeof motionQuery.addListener === 'function') motionQuery.addListener(sync);
    sync();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, { once: true });
  else init();
})();
