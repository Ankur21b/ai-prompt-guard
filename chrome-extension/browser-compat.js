/**
 * AI Prompt Guard — Cross-browser compatibility shim
 *
 * Firefox exposes both `browser` (promise-based) and `chrome` (callback alias).
 * Chrome only exposes `chrome`.
 * Edge and other Chromium browsers expose only `chrome`.
 *
 * This file sets `globalThis._b` to `browser` when available (Firefox), falling
 * back to `chrome`.  All extension JS files use `_b` instead of `chrome` so the
 * same source runs unmodified in Chrome, Firefox, and Edge.
 *
 * Loaded first in manifest content_scripts and in popup.html.
 */

// eslint-disable-next-line no-undef
globalThis._b = (typeof browser !== 'undefined' && browser?.runtime) ? browser : chrome;
