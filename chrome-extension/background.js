// Service worker — minimal. Handles messages from content script.
/* global chrome, browser */

const _b = (typeof browser !== 'undefined' && browser?.runtime) ? browser : chrome;

_b.runtime.onInstalled.addListener(() => {
  _b.storage.local.set({
    enabled: true,
    totalScans: 0,
    totalPiiBlocked: 0,
  });
});

// Relay stats updates from content script
_b.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'PG_SCAN_RESULT') {
    _b.storage.local.get(['totalScans', 'totalPiiBlocked'], (data) => {
      const newScans = (data.totalScans || 0) + 1;
      const newPii   = (data.totalPiiBlocked || 0) + (msg.piiFound ? 1 : 0);
      _b.storage.local.set({ totalScans: newScans, totalPiiBlocked: newPii });
    });
    sendResponse({ ok: true });
  }
  return true;
});
