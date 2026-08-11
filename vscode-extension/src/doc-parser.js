'use strict';

/**
 * Document text extractor + sanitizer for PII Guard
 * Supports: PDF (.pdf), Word (.docx), Excel (.xlsx / .xls / .csv)
 */

const fs   = require('fs');
const path = require('path');
const zlib = require('zlib');

/**
 * Extract plain text from a file based on its extension.
 * Returns { text, pageCount, sheetNames } — pageCount / sheetNames may be undefined.
 */
async function extractText(filePath) {
  const ext = path.extname(filePath).toLowerCase();

  switch (ext) {
    case '.pdf':  return extractPdf(filePath);
    case '.docx': return extractDocx(filePath);
    case '.doc':  return extractDocx(filePath);
    case '.xlsx':
    case '.xls':  return extractExcel(filePath);
    case '.csv':  return extractCsv(filePath);
    default:
      return { text: fs.readFileSync(filePath, 'utf8') };
  }
}

/**
 * Create a sanitized (or encrypted) copy of a file with PII replaced.
 * Returns the output file path, or null for unsupported types (PDF).
 *
 * @param {string}   filePath    - original file path
 * @param {object[]} detections  - from detect()
 * @param {string}   sanitized   - full sanitized plain text (for Excel / CSV)
 * @param {'sanitize'|'encrypt'} mode
 * @param {Map}      encryptMap  - value → encrypted token (used when mode='encrypt')
 */
async function createSanitizedCopy(filePath, detections, sanitizedText, mode = 'sanitize', encryptMap = null) {
  const ext    = path.extname(filePath).toLowerCase();
  const dir    = path.dirname(filePath);
  const base   = path.basename(filePath, ext);
  const suffix = mode === 'encrypt' ? '_encrypted' : '_sanitized';
  const outPath = path.join(dir, `${base}${suffix}${ext}`);

  switch (ext) {
    case '.docx':
    case '.doc':
      await sanitizeDocxFile(filePath, outPath, detections, mode, encryptMap);
      return outPath;

    case '.xlsx':
    case '.xls':
      sanitizeXlsxFile(filePath, outPath, detections, mode, encryptMap);
      return outPath;

    case '.csv':
    case '.txt':
    case '.md':
    case '.log':
    case '.json':
    case '.xml':
    case '.html': {
      const original = fs.readFileSync(filePath, 'utf8');
      const result   = applyReplacements(original, detections, mode, encryptMap);
      fs.writeFileSync(outPath, result, 'utf8');
      return outPath;
    }

    case '.pdf':
      return null; // Binary layout-dependent — cannot safely replace text

    default: {
      const original = fs.readFileSync(filePath, 'utf8');
      const result   = applyReplacements(original, detections, mode, encryptMap);
      fs.writeFileSync(outPath, result, 'utf8');
      return outPath;
    }
  }
}

// ── DOCX sanitization (ZIP/XML rebuild using Node built-in zlib) ─────────────

async function sanitizeDocxFile(filePath, outPath, detections, mode, encryptMap) {
  const src = fs.readFileSync(filePath);

  // Parse all ZIP local-file entries
  const entries = parseZipEntries(src);

  // Modify word/document.xml
  const modified = entries.map(entry => {
    if (entry.name !== 'word/document.xml') return entry;

    let xml;
    if (entry.compression === 0) {
      xml = entry.data.toString('utf8');
    } else if (entry.compression === 8) {
      xml = zlib.inflateRawSync(entry.data).toString('utf8');
    } else {
      return entry; // unknown compression — leave untouched
    }

    // Replace PII values directly in the XML text
    xml = applyReplacements(xml, detections, mode, encryptMap);

    const newData       = Buffer.from(xml, 'utf8');
    const compressed    = zlib.deflateRawSync(newData, { level: 6 });
    const newCrc        = crc32(newData);
    return { ...entry, data: compressed, compSize: compressed.length, uncompSize: newData.length, crc: newCrc, compression: 8 };
  });

  // Rebuild ZIP and write output
  const outBuf = buildZip(modified);
  fs.writeFileSync(outPath, outBuf);
}

// ── XLSX sanitization (using xlsx library) ───────────────────────────────────

function sanitizeXlsxFile(filePath, outPath, detections, mode, encryptMap) {
  const XLSX     = require('xlsx');
  const workbook = XLSX.readFile(filePath);

  for (const sheetName of workbook.SheetNames) {
    const sheet = workbook.Sheets[sheetName];
    for (const cellAddr of Object.keys(sheet)) {
      if (cellAddr[0] === '!') continue; // skip metadata keys
      const cell = sheet[cellAddr];
      if (cell.t === 's' || cell.t === 'str') { // string cell
        cell.v = applyReplacements(String(cell.v), detections, mode, encryptMap);
        cell.w = cell.v; // formatted value
      }
    }
  }

  XLSX.writeFile(workbook, outPath);
}

// ── Replacement helper ────────────────────────────────────────────────────────

function applyReplacements(text, detections, mode, encryptMap) {
  let result = text;
  // Sort detections longest-first to avoid partial replacements of substrings
  const sorted = [...detections].sort((a, b) => b.value.length - a.value.length);
  for (const d of sorted) {
    const replacement = mode === 'encrypt' && encryptMap
      ? (encryptMap.get(d.value) || `[ENC:${d.category}:???]`)
      : `[${d.label.toUpperCase().replace(/ /g, '_')}_REDACTED]`;
    result = result.split(d.value).join(replacement);
  }
  return result;
}

// ── Minimal ZIP parser ────────────────────────────────────────────────────────

function parseZipEntries(buf) {
  const entries = [];
  let offset = 0;

  while (offset < buf.length - 30) {
    if (buf.readUInt32LE(offset) !== 0x04034b50) break;

    const compression = buf.readUInt16LE(offset + 8);
    const crc         = buf.readUInt32LE(offset + 14);
    const compSize    = buf.readUInt32LE(offset + 18);
    const uncompSize  = buf.readUInt32LE(offset + 22);
    const nameLen     = buf.readUInt16LE(offset + 26);
    const extraLen    = buf.readUInt16LE(offset + 28);
    const name        = buf.slice(offset + 30, offset + 30 + nameLen).toString('utf8');
    const dataStart   = offset + 30 + nameLen + extraLen;
    const data        = buf.slice(dataStart, dataStart + compSize);

    entries.push({ name, compression, crc, compSize, uncompSize, nameLen, extraLen, data });
    offset = dataStart + compSize;
  }

  return entries;
}

// ── Minimal ZIP builder ───────────────────────────────────────────────────────

function buildZip(entries) {
  const parts = [];
  const centralDirEntries = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuf  = Buffer.from(entry.name, 'utf8');
    const localHdr = Buffer.alloc(30 + nameBuf.length);

    localHdr.writeUInt32LE(0x04034b50, 0);        // signature
    localHdr.writeUInt16LE(20,          4);        // version needed
    localHdr.writeUInt16LE(0,           6);        // flags
    localHdr.writeUInt16LE(entry.compression, 8); // compression method
    localHdr.writeUInt16LE(0,           10);       // mod time
    localHdr.writeUInt16LE(0,           12);       // mod date
    localHdr.writeUInt32LE(entry.crc,   14);       // CRC-32
    localHdr.writeUInt32LE(entry.compSize,  18);   // compressed size
    localHdr.writeUInt32LE(entry.uncompSize, 22);  // uncompressed size
    localHdr.writeUInt16LE(nameBuf.length,  26);   // filename length
    localHdr.writeUInt16LE(0,           28);       // extra field length
    nameBuf.copy(localHdr, 30);

    parts.push(localHdr, entry.data);

    // Central directory entry
    const cdEntry = Buffer.alloc(46 + nameBuf.length);
    cdEntry.writeUInt32LE(0x02014b50, 0);
    cdEntry.writeUInt16LE(20,          4);
    cdEntry.writeUInt16LE(20,          6);
    cdEntry.writeUInt16LE(0,           8);
    cdEntry.writeUInt16LE(entry.compression, 10);
    cdEntry.writeUInt16LE(0,           12);
    cdEntry.writeUInt16LE(0,           14);
    cdEntry.writeUInt32LE(entry.crc,   16);
    cdEntry.writeUInt32LE(entry.compSize,  20);
    cdEntry.writeUInt32LE(entry.uncompSize, 24);
    cdEntry.writeUInt16LE(nameBuf.length,  28);
    cdEntry.writeUInt16LE(0,           30);
    cdEntry.writeUInt16LE(0,           32);
    cdEntry.writeUInt16LE(0,           34);
    cdEntry.writeUInt16LE(0,           36);
    cdEntry.writeUInt32LE(0,           38);
    cdEntry.writeUInt32LE(localOffset, 42);
    nameBuf.copy(cdEntry, 46);

    centralDirEntries.push(cdEntry);
    localOffset += localHdr.length + entry.data.length;
  }

  const cdBuf    = Buffer.concat(centralDirEntries);
  const eocd     = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0,          4);
  eocd.writeUInt16LE(0,          6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdBuf.length,   12);
  eocd.writeUInt32LE(localOffset,    16);
  eocd.writeUInt16LE(0,              20);

  return Buffer.concat([...parts, cdBuf, eocd]);
}

// ── CRC-32 (required for valid ZIP files) ────────────────────────────────────

const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[i] = c;
  }
  return t;
})();

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) crc = CRC32_TABLE[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

// ── PDF ──────────────────────────────────────────────────────────────────────

async function extractPdf(filePath) {
  const pdfParse = require('pdf-parse');
  const buffer   = fs.readFileSync(filePath);
  const data     = await pdfParse(buffer);
  return {
    text:      data.text,
    pageCount: data.numpages,
    info:      data.info,
  };
}

// ── Word (.docx) ─────────────────────────────────────────────────────────────

async function extractDocx(filePath) {
  const mammoth = require('mammoth');
  const result  = await mammoth.extractRawText({ path: filePath });
  return {
    text:     result.value,
    warnings: result.messages,
  };
}

// ── Excel (.xlsx / .xls) ─────────────────────────────────────────────────────

async function extractExcel(filePath) {
  const XLSX       = require('xlsx');
  const workbook   = XLSX.readFile(filePath);
  const sheetNames = workbook.SheetNames;

  const parts = sheetNames.map(name => {
    const sheet = workbook.Sheets[name];
    const rows  = XLSX.utils.sheet_to_csv(sheet);
    return `[Sheet: ${name}]\n${rows}`;
  });

  return {
    text:       parts.join('\n\n'),
    sheetNames,
  };
}

// ── CSV ───────────────────────────────────────────────────────────────────────

async function extractCsv(filePath) {
  return { text: fs.readFileSync(filePath, 'utf8') };
}

// ── Supported types helper ───────────────────────────────────────────────────

const SUPPORTED_EXTENSIONS = ['.pdf', '.docx', '.doc', '.xlsx', '.xls', '.csv'];

function isSupported(filePath) {
  return SUPPORTED_EXTENSIONS.includes(path.extname(filePath).toLowerCase());
}

function supportedLabel(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const map = {
    '.pdf':  'PDF',
    '.docx': 'Word',
    '.doc':  'Word',
    '.xlsx': 'Excel',
    '.xls':  'Excel',
    '.csv':  'CSV',
  };
  return map[ext] || 'Document';
}

// PDF cannot be sanitized (binary layout-dependent)
function canSanitize(filePath) {
  return path.extname(filePath).toLowerCase() !== '.pdf';
}

module.exports = { extractText, createSanitizedCopy, isSupported, canSanitize, supportedLabel, SUPPORTED_EXTENSIONS };
