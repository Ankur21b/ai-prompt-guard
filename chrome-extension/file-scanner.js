/**
 * AI Prompt Guard — File Scanner
 * Reads attached files, scans for PII, and produces sanitized replacements.
 * Loaded before content.js. Exposes: window.FileScanner
 *
 * Supported formats:
 *   Sanitizable:  .txt .md .csv .log .json .xml .html .htm .py .js .ts
 *   Sanitizable:  .docx  (ZIP/XML rebuilt with PII replaced — no external lib)
 *   Scan-only:    .pdf   (text extracted from PDF streams; binary not rebuilt)
 *   Unsupported:  .xlsx .pptx etc.
 */
(function () {
  'use strict';

  // ── Public API ────────────────────────────────────────────────────────────

  window.FileScanner = { scanFiles };

  /**
   * Scan an array / FileList of files.
   * @returns Promise<FileResult[]>
   */
  async function scanFiles(fileList) {
    const files = Array.from(fileList);
    return Promise.all(files.map(scanFile));
  }

  // ── Per-file scanner ──────────────────────────────────────────────────────

  async function scanFile(file) {
    const ext  = (file.name.split('.').pop() || '').toLowerCase();
    const base = { file, name: file.name };

    try {
      if (isTextBased(ext, file.type)) {
        return await scanTextFile(file, base);
      }
      if (ext === 'pdf') {
        return await scanPdfFile(file, base);
      }
      if (ext === 'docx' || ext === 'doc') {
        return await scanDocxFile(file, base);
      }
      // Unsupported binary (xlsx, pptx…)
      return { ...base, kind: 'unsupported', found: false, categories: [], regulations: [], canSanitize: false, sanitizedFile: null };
    } catch (err) {
      return { ...base, kind: 'error', error: err.message, found: false, categories: [], regulations: [], canSanitize: false, sanitizedFile: null };
    }
  }

  // ── Text files ────────────────────────────────────────────────────────────

  const TEXT_EXTENSIONS = new Set([
    'txt','md','csv','tsv','log','json','xml','html','htm',
    'py','js','ts','jsx','tsx','yaml','yml','toml','ini','cfg',
    'sql','sh','bash','zsh','env','gitignore',
  ]);

  function isTextBased(ext, mimeType) {
    return TEXT_EXTENSIONS.has(ext) || (mimeType && mimeType.startsWith('text/'));
  }

  async function scanTextFile(file, base) {
    const text   = await readAsText(file);
    const result = window.PiiDetector.detect(text);

    return {
      ...base,
      kind:         'text',
      canSanitize:  true,
      found:        result.found,
      categories:   result.categories,
      regulations:  result.regulations,
      detections:   result.detections,
      originalText: text,
      sanitizedText: result.sanitizedText,
      sanitizedFile: result.found ? makeTextFile(file, result.sanitizedText) : null,
    };
  }

  // ── DOCX files ────────────────────────────────────────────────────────────
  // DOCX = ZIP containing word/document.xml. We parse the ZIP local-file
  // headers in the browser (no lib), decompress with DecompressionStream,
  // then strip XML tags to extract plain text.

  async function scanDocxFile(file, base) {
    const buffer = await file.arrayBuffer();
    const text   = await extractDocxText(file);
    const result = window.PiiDetector.detect(text);

    let sanitizedFile = null;
    if (result.found) {
      try {
        const sanitizedBuf = await sanitizeDocxBuffer(buffer, result.detections);
        const sanitizedName = file.name.replace(/(\.[^.]+)$/, '_sanitized$1');
        sanitizedFile = new File([sanitizedBuf], sanitizedName, { type: file.type, lastModified: Date.now() });
      } catch (_) {
        // ZIP rebuild failed — fall back to scan-only
      }
    }

    return {
      ...base,
      kind:         'docx',
      canSanitize:  true,
      found:        result.found,
      categories:   result.categories,
      regulations:  result.regulations,
      detections:   result.detections || [],
      extractedText: text,
      sanitizedText: result.sanitizedText,
      sanitizedFile,
    };
  }

  // Replace PII values in the raw ZIP/XML and return a new ArrayBuffer
  async function sanitizeDocxBuffer(buffer, detections) {
    const bytes   = new Uint8Array(buffer);
    const entries = parseZipEntries(bytes);

    const modified = await Promise.all(entries.map(async entry => {
      if (entry.name !== 'word/document.xml') return entry;

      let xml;
      if (entry.compression === 0) {
        xml = new TextDecoder('utf-8').decode(entry.data);
      } else if (entry.compression === 8) {
        xml = new TextDecoder('utf-8').decode(await decompressRaw(entry.data));
      } else {
        return entry;
      }

      // Replace each PII value in the XML text
      const sorted = [...detections].sort((a, b) => b.value.length - a.value.length);
      for (const d of sorted) {
        const replacement = `[${d.label.toUpperCase().replace(/ /g, '_')}_REDACTED]`;
        xml = xml.split(d.value).join(replacement);
      }

      const newBytes   = new TextEncoder().encode(xml);
      const compressed = await compressRaw(newBytes);
      return { ...entry, data: compressed, compSize: compressed.length, uncompSize: newBytes.length, crc: crc32(newBytes), compression: 8 };
    }));

    return buildZip(modified);
  }

  async function extractDocxText(file) {
    const buffer = await file.arrayBuffer();
    const bytes  = new Uint8Array(buffer);
    const view   = new DataView(buffer);

    const chunks = [];
    let offset = 0;

    // Walk ZIP local file headers (signature 0x04034b50)
    while (offset < bytes.length - 30) {
      const sig = view.getUint32(offset, true);
      if (sig !== 0x04034b50) { offset++; continue; }

      const compression   = view.getUint16(offset + 8,  true);
      const compSize      = view.getUint32(offset + 18, true);
      const uncompSize    = view.getUint32(offset + 22, true);
      const fileNameLen   = view.getUint16(offset + 26, true);
      const extraFieldLen = view.getUint16(offset + 28, true);
      const dataOffset    = offset + 30 + fileNameLen + extraFieldLen;

      const entryName = new TextDecoder().decode(bytes.slice(offset + 30, offset + 30 + fileNameLen));

      // Only parse the main document body — skip headers/footers/styles
      if (entryName === 'word/document.xml') {
        const compData = bytes.slice(dataOffset, dataOffset + compSize);
        let xmlText;

        if (compression === 0) {
          // Stored (no compression)
          xmlText = new TextDecoder('utf-8').decode(compData);
        } else if (compression === 8 && typeof DecompressionStream !== 'undefined') {
          // Deflate — use native DecompressionStream (Chrome 80+)
          try {
            const ds     = new DecompressionStream('deflate-raw');
            const writer = ds.writable.getWriter();
            const reader = ds.readable.getReader();
            writer.write(compData);
            writer.close();

            const parts = [];
            let   done  = false;
            while (!done) {
              const { value, done: d } = await reader.read();
              if (value) parts.push(value);
              done = d;
            }
            const out = new Uint8Array(parts.reduce((acc, p) => acc + p.byteLength, 0));
            let pos = 0;
            for (const p of parts) { out.set(p, pos); pos += p.byteLength; }
            xmlText = new TextDecoder('utf-8').decode(out);
          } catch (_) {
            // DecompressionStream failed — fall through to raw ASCII scan
            xmlText = new TextDecoder('latin1').decode(compData);
          }
        } else {
          // Unknown compression — try raw latin1 decode as last resort
          xmlText = new TextDecoder('latin1').decode(compData);
        }

        // Strip XML tags, decode common entities, collapse whitespace
        const plain = xmlText
          .replace(/<w:p[ >][^>]*>/gi, '\n')   // paragraph → newline
          .replace(/<[^>]+>/g, ' ')             // all other tags → space
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&quot;/g, '"')
          .replace(/&apos;/g, "'")
          .replace(/&#x([0-9A-Fa-f]+);/g, (_, h) => String.fromCodePoint(parseInt(h, 16)))
          .replace(/\s+/g, ' ')
          .trim();

        chunks.push(plain);
        break; // Found and processed word/document.xml — done
      }

      offset = dataOffset + compSize;
    }

    return chunks.join('\n');
  }

  // ── ZIP utilities (used by DOCX sanitizer) ────────────────────────────────

  function parseZipEntries(bytes) {
    const view    = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const entries = [];
    let offset    = 0;

    while (offset < bytes.length - 30) {
      if (view.getUint32(offset, true) !== 0x04034b50) break;

      const compression = view.getUint16(offset + 8,  true);
      const crc         = view.getUint32(offset + 14, true);
      const compSize    = view.getUint32(offset + 18, true);
      const uncompSize  = view.getUint32(offset + 22, true);
      const nameLen     = view.getUint16(offset + 26, true);
      const extraLen    = view.getUint16(offset + 28, true);
      const name        = new TextDecoder().decode(bytes.slice(offset + 30, offset + 30 + nameLen));
      const dataStart   = offset + 30 + nameLen + extraLen;
      const data        = bytes.slice(dataStart, dataStart + compSize);

      entries.push({ name, compression, crc, compSize, uncompSize, data });
      offset = dataStart + compSize;
    }
    return entries;
  }

  function buildZip(entries) {
    const localParts  = [];
    const cdParts     = [];
    let   localOffset = 0;

    for (const entry of entries) {
      const nameBytes = new TextEncoder().encode(entry.name);
      const lhSize    = 30 + nameBytes.length;
      const lh        = new Uint8Array(lhSize);
      const lv        = new DataView(lh.buffer);

      lv.setUint32(0,  0x04034b50,       true);
      lv.setUint16(4,  20,               true);
      lv.setUint16(6,  0,                true);
      lv.setUint16(8,  entry.compression,true);
      lv.setUint16(10, 0,                true);
      lv.setUint16(12, 0,                true);
      lv.setUint32(14, entry.crc,        true);
      lv.setUint32(18, entry.compSize,   true);
      lv.setUint32(22, entry.uncompSize, true);
      lv.setUint16(26, nameBytes.length, true);
      lv.setUint16(28, 0,                true);
      lh.set(nameBytes, 30);

      localParts.push(lh, entry.data);

      const cd = new Uint8Array(46 + nameBytes.length);
      const cv = new DataView(cd.buffer);
      cv.setUint32(0,  0x02014b50,        true);
      cv.setUint16(4,  20,                true);
      cv.setUint16(6,  20,                true);
      cv.setUint16(8,  0,                 true);
      cv.setUint16(10, entry.compression, true);
      cv.setUint16(12, 0,                 true);
      cv.setUint16(14, 0,                 true);
      cv.setUint32(16, entry.crc,         true);
      cv.setUint32(20, entry.compSize,    true);
      cv.setUint32(24, entry.uncompSize,  true);
      cv.setUint16(28, nameBytes.length,  true);
      cv.setUint16(30, 0,  true); cv.setUint16(32, 0, true);
      cv.setUint16(34, 0,  true); cv.setUint16(36, 0, true);
      cv.setUint32(38, 0,  true);
      cv.setUint32(42, localOffset,       true);
      cd.set(nameBytes, 46);
      cdParts.push(cd);

      localOffset += lhSize + entry.data.length;
    }

    const cdSize  = cdParts.reduce((s, p) => s + p.length, 0);
    const eocd    = new Uint8Array(22);
    const ev      = new DataView(eocd.buffer);
    ev.setUint32(0,  0x06054b50,      true);
    ev.setUint16(4,  0,               true);
    ev.setUint16(6,  0,               true);
    ev.setUint16(8,  entries.length,  true);
    ev.setUint16(10, entries.length,  true);
    ev.setUint32(12, cdSize,          true);
    ev.setUint32(16, localOffset,     true);
    ev.setUint16(20, 0,               true);

    const all   = [...localParts, ...cdParts, eocd];
    const total = all.reduce((s, p) => s + p.length, 0);
    const out   = new Uint8Array(total);
    let pos = 0;
    for (const p of all) { out.set(p, pos); pos += p.length; }
    return out.buffer;
  }

  async function decompressRaw(data) {
    const ds     = new DecompressionStream('deflate-raw');
    const writer = ds.writable.getWriter();
    const reader = ds.readable.getReader();
    writer.write(data); writer.close();
    const parts = [];
    let done = false;
    while (!done) { const { value, done: d } = await reader.read(); if (value) parts.push(value); done = d; }
    const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
    let pos = 0; for (const p of parts) { out.set(p, pos); pos += p.length; }
    return out;
  }

  async function compressRaw(data) {
    const cs     = new CompressionStream('deflate-raw');
    const writer = cs.writable.getWriter();
    const reader = cs.readable.getReader();
    writer.write(data); writer.close();
    const parts = [];
    let done = false;
    while (!done) { const { value, done: d } = await reader.read(); if (value) parts.push(value); done = d; }
    const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
    let pos = 0; for (const p of parts) { out.set(p, pos); pos += p.length; }
    return out;
  }

  // CRC-32 (required for valid ZIP local and central directory headers)
  const CRC32_TABLE = (() => {
    const t = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      t[i] = c;
    }
    return t;
  })();

  function crc32(data) {
    let crc = 0xFFFFFFFF;
    for (let i = 0; i < data.length; i++) crc = CRC32_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  // ── PDF files ─────────────────────────────────────────────────────────────
  // Extracts visible text from PDF byte streams without external libraries.
  // Covers PDFs with uncompressed text streams and UTF-8 / Latin-1 encoding.
  // Complex PDFs with compressed streams or Type3 fonts may yield partial text.

  async function scanPdfFile(file, base) {
    const text   = await extractPdfText(file);
    const result = window.PiiDetector.detect(text);

    return {
      ...base,
      kind:         'pdf',
      canSanitize:  false,   // Rebuilding PDF binary requires a full PDF lib
      found:        result.found,
      categories:   result.categories,
      regulations:  result.regulations,
      detections:   result.detections,
      extractedText: text,
      sanitizedText: result.sanitizedText,
      sanitizedFile: null,
    };
  }

  async function extractPdfText(file) {
    const buffer  = await file.arrayBuffer();
    const bytes   = new Uint8Array(buffer);
    const decoder = new TextDecoder('latin1');
    const raw     = decoder.decode(bytes);

    const chunks = [];

    // 1. Extract text between BT … ET (PDF text object markers)
    const btEtRe = /BT\s([\s\S]*?)ET/g;
    let m;
    while ((m = btEtRe.exec(raw)) !== null) {
      // Literal strings: (text)
      const litRe = /\(((?:[^\\)\\\\]|\\.)*)\)/g;
      let l;
      while ((l = litRe.exec(m[1])) !== null) {
        chunks.push(
          l[1]
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\r')
            .replace(/\\t/g, '\t')
            .replace(/\\\\/g, '\\')
            .replace(/\\([()\\])/g, '$1')
        );
      }
      // Hex strings: <4865> → "He"
      const hexRe = /<([0-9A-Fa-f]+)>/g;
      let h;
      while ((h = hexRe.exec(m[1])) !== null) {
        const hex = h[1];
        let str = '';
        for (let i = 0; i < hex.length - 1; i += 2) {
          str += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        }
        chunks.push(str);
      }
    }

    // 2. Fallback: scan for plain ASCII runs (catches metadata, annotations)
    if (chunks.length === 0) {
      const asciiRe = /[\x20-\x7E]{6,}/g;
      let a;
      while ((a = asciiRe.exec(raw)) !== null) {
        chunks.push(a[0]);
      }
    }

    return chunks.join(' ').replace(/\s+/g, ' ').trim();
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  function readAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload  = e => resolve(e.target.result);
      reader.onerror = () => reject(new Error('FileReader error'));
      reader.readAsText(file, 'UTF-8');
    });
  }

  function makeTextFile(originalFile, sanitizedText) {
    const sanitizedName = originalFile.name.replace(/(\.[^.]+)$/, '_sanitized$1');
    return new File([sanitizedText], sanitizedName, {
      type: originalFile.type || 'text/plain',
      lastModified: Date.now(),
    });
  }
})();
