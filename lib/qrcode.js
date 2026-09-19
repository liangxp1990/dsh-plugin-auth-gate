/**
 * Minimal QR encoder — byte mode, versions 1–7, error-correction level L
 * (up to 154 payload bytes, ample for an otpauth:// provisioning URI; v6/v7
 * use the spec's multi-block interleaved Reed–Solomon layout). SVG output for
 * the MFA setup page.
 * @module dsh-plugin-auth-gate/qrcode
 */

//#region GF(256) arithmetic
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();
const gfMul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);
//#endregion

//#region per-version constants (EC level L)
// version → { size, blocks: [count, dataCodewordsPerBlock, ecCodewordsPerBlock] }
const SPECS = [
  null,
  { size: 21, blocks: [1, 19, 7] },
  { size: 25, blocks: [1, 34, 10] },
  { size: 29, blocks: [1, 55, 15] },
  { size: 33, blocks: [1, 80, 20] },
  { size: 37, blocks: [1, 108, 26] },
  { size: 41, blocks: [2, 68, 18] },
  { size: 45, blocks: [4, 39, 10] }
];
const ALIGN_CENTERS = [null, null, [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38]];
const EC_LEVEL_L_BITS = 1; // format-info EC indicator for L is 01
//#endregion

function rsGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

function rsRemainder(data, ecLength) {
  const generator = rsGeneratorPoly(ecLength);
  const remainder = new Uint8Array(ecLength);
  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[ecLength - 1] = 0;
    for (let i = 0; i < ecLength; i++) remainder[i] ^= gfMul(generator[i + 1], factor);
  }
  return remainder;
}

function encodeData(text, spec) {
  const bytes = Buffer.from(text, 'utf8');
  const dataCodewords = spec.blocks[0] * spec.blocks[1];
  const capacityBits = dataCodewords * 8;
  const headerBits = 4 + 8; // byte-mode indicator + 8-bit count (v1–v9)
  if (bytes.length > dataCodewords - 2) throw new Error('payload too long for QR v1–v7 byte mode');
  const bits = [];
  const push = (value, count) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };
  push(4, 4); // byte mode
  push(bytes.length, 8);
  for (const byte of bytes) push(byte, 8);
  const used = headerBits + bytes.length * 8;
  for (let i = 0; i < Math.min(4, capacityBits - used); i++) bits.push(0); // terminator
  while (bits.length % 8 !== 0) bits.push(0);
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }
  const pads = [0xec, 0x11];
  let pad = 0;
  while (codewords.length < dataCodewords) codewords.push(pads[pad++ % 2]);
  return Uint8Array.from(codewords);
}

/** Split data across RS blocks, compute each block's EC, and interleave per spec. */
function interleave(data, [count, dataPerBlock, ecPerBlock]) {
  const blocks = [];
  const eccBlocks = [];
  for (let b = 0; b < count; b++) {
    const slice = data.subarray(b * dataPerBlock, (b + 1) * dataPerBlock);
    blocks.push(slice);
    eccBlocks.push(rsRemainder(slice, ecPerBlock));
  }
  const output = [];
  for (let i = 0; i < dataPerBlock; i++) {
    for (const block of blocks) output.push(block[i]);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const block of eccBlocks) output.push(block[i]);
  }
  return Buffer.from(output);
}

function formatBits(mask) {
  const data = (EC_LEVEL_L_BITS << 3) | mask;
  let remainder = data;
  for (let i = 0; i < 10; i++) remainder = (remainder << 1) ^ ((remainder >> 9) & 1) * 0x537;
  return ((data << 10) | remainder) ^ 0x5412;
}

function buildMatrix(text, spec, version, mask) {
  const size = spec.size;
  const matrix = Array.from({ length: size }, () => new Array(size).fill(null));
  const reserved = Array.from({ length: size }, () => new Array(size).fill(false));

  const setFinder = (row, col) => {
    for (let r = -1; r <= 7; r++) {
      for (let c = -1; c <= 7; c++) {
        const rr = row + r;
        const cc = col + c;
        if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
        const inRing =
          (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
          (c >= 0 && c <= 6 && (r === 0 || r === 6));
        const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        matrix[rr][cc] = inRing || inCore ? 1 : 0;
        reserved[rr][cc] = true;
      }
    }
  };
  setFinder(0, 0);
  setFinder(0, size - 7);
  setFinder(size - 7, 0);

  for (let i = 8; i < size - 8; i++) {
    if (matrix[6][i] === null) matrix[6][i] = i % 2 === 0 ? 1 : 0;
    if (matrix[i][6] === null) matrix[i][6] = i % 2 === 0 ? 1 : 0;
    reserved[6][i] = true;
    reserved[i][6] = true;
  }

  const centers = ALIGN_CENTERS[version] ?? [];
  for (const row of centers) {
    for (const col of centers) {
      if (matrix[row][col] !== null) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const ring = Math.max(Math.abs(r), Math.abs(c));
          matrix[row + r][col + c] = ring === 1 ? 0 : 1;
          reserved[row + r][col + c] = true;
        }
      }
    }
  }

  matrix[size - 8][8] = 1; // dark module
  reserved[size - 8][8] = true;

  // reserve format-info cells
  for (let i = 0; i <= 7; i++) reserved[i][8] = true;       // copy 1 vertical leg
  for (let i = 0; i <= 5; i++) reserved[8][i] = true;       // copy 1 horizontal leg
  reserved[8][7] = true;
  reserved[8][8] = true;
  for (let i = 0; i < 8; i++) reserved[8][size - 1 - i] = true;   // copy 2 horizontal leg
  for (let i = 8; i < 15; i++) reserved[size - 15 + i][8] = true; // copy 2 vertical leg

  // data + EC codewords into the zigzag
  const data = encodeData(text, spec);
  const codewords = interleave(data, spec.blocks);
  const bits = [];
  for (const byte of codewords) for (let i = 7; i >= 0; i--) bits.push((byte >>> i) & 1);
  let bitIndex = 0;
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // skip the timing column entirely
    const left = right - 1;
    for (let i = 0; i < size; i++) {
      const row = upward ? size - 1 - i : i;
      for (const col of [right, left]) {
        if (!reserved[row][col]) {
          matrix[row][col] = bitIndex < bits.length ? bits[bitIndex] : 0;
          bitIndex++;
        }
      }
    }
    upward = !upward;
  }

  // apply the chosen mask
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (reserved[row][col]) continue;
      if (maskBit(mask, row, col)) matrix[row][col] ^= 1;
    }
  }

  // format info, both copies
  const format = formatBits(mask);
  for (let i = 0; i <= 5; i++) matrix[i][8] = (format >> i) & 1;
  matrix[7][8] = (format >> 6) & 1;
  matrix[8][8] = (format >> 7) & 1;
  matrix[8][7] = (format >> 8) & 1;
  for (let i = 9; i <= 14; i++) matrix[8][14 - i] = (format >> i) & 1;
  for (let i = 0; i < 8; i++) matrix[8][size - 1 - i] = (format >> i) & 1;
  for (let i = 8; i < 15; i++) matrix[size - 15 + i][8] = (format >> i) & 1;

  return matrix;
}

function maskBit(mask, row, col) {
  switch (mask) {
    case 0: return (row + col) % 2 === 0;
    case 1: return row % 2 === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return (Math.floor(row / 2) + Math.floor(col / 3)) % 2 === 0;
    case 5: return ((row * col) % 2) + ((row * col) % 3) === 0;
    case 6: return (((row * col) % 2) + ((row * col) % 3)) % 2 === 0;
    default: return (((row + col) % 2) + ((row * col) % 3)) % 2 === 0;
  }
}

function penalty(matrix) {
  const size = matrix.length;
  let score = 0;
  // rule 1: runs of 5+ same colour in rows and columns
  for (let axis = 0; axis < 2; axis++) {
    for (let i = 0; i < size; i++) {
      let run = 1;
      let previous = null;
      for (let j = 0; j < size; j++) {
        const cell = axis === 0 ? matrix[i][j] : matrix[j][i];
        if (cell === previous) {
          run++;
          if (run === 5) score += 3;
          else if (run > 5) score += 1;
        } else {
          previous = cell;
          run = 1;
        }
      }
    }
  }
  // rule 2: 2×2 same-colour blocks
  for (let row = 0; row < size - 1; row++) {
    for (let col = 0; col < size - 1; col++) {
      const cell = matrix[row][col];
      if (cell === matrix[row][col + 1] && cell === matrix[row + 1][col] && cell === matrix[row + 1][col + 1]) score += 3;
    }
  }
  // rule 4: dark proportion
  let dark = 0;
  for (const row of matrix) for (const cell of row) dark += cell;
  score += Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
  return score;
}

/** Encode text to a module matrix, choosing the lowest-penalty mask. */
export function encodeMatrix(text) {
  let version = 0;
  for (let v = 1; v < SPECS.length; v++) {
    try {
      encodeData(text, SPECS[v]);
      version = v;
      break;
    } catch {
      // try the next size up
    }
  }
  if (version === 0) throw new Error('payload exceeds QR v7-L byte-mode capacity (154 bytes)');
  const spec = SPECS[version];
  let best = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const matrix = buildMatrix(text, spec, version, mask);
    const score = penalty(matrix);
    if (score < bestScore) {
      bestScore = score;
      best = matrix;
    }
  }
  return { matrix: best, version, mask: bestScore === Infinity ? 0 : undefined };
}

/** Render the matrix as a crisp black-on-transparent SVG string. */
export function encodeSvg(text, { border = 4, scale = 6, dark = '#000' } = {}) {
  const { matrix } = encodeMatrix(text);
  const size = matrix.length;
  const dimension = (size + border * 2) * scale;
  let path = '';
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (matrix[row][col]) {
        path += `M${(col + border) * scale} ${(row + border) * scale}h${scale}v${scale}h${-scale}z`;
      }
    }
  }
  return (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + dimension + ' ' + dimension + '" ' +
    'shape-rendering="crispEdges" width="' + dimension + '" height="' + dimension + '" role="img" aria-label="QR code">' +
    '<rect width="100%" height="100%" fill="#fff"/>' +
    '<path d="' + path + '" fill="' + dark + '"/>' +
    '</svg>'
  );
}
