export const FRAME_LENGTH = 10;
export const MAX_PREVIEW_FRAMES = 100;
export const MAX_MESSAGE_LENGTH = 500;
// Stored (encrypted) payloads are longer than the plaintext they carry:
// "e1." + base64(IV + ciphertext + tag). 500 ASCII characters need 707 characters.
export const MAX_PAYLOAD_LENGTH = 800;

/**
 * SYNTRIX uses printable 7-bit ASCII. A frame is:
 * start(0) + data(7) + even-parity(1) + stop(1) = 10 bits.
 */
export function buildFrames(text, { maxLength = MAX_MESSAGE_LENGTH } = {}) {
  if (typeof text !== 'string' || text.length === 0) {
    throw new Error('Pesan tidak boleh kosong.');
  }
  if (text.length > maxLength) {
    throw new Error(`Pesan maksimal ${maxLength} karakter.`);
  }
  if (!/^[\x20-\x7E]+$/.test(text)) {
    throw new Error('Gunakan karakter ASCII yang dapat dicetak. Emoji dan huruf non-ASCII belum didukung.');
  }

  return Array.from(text, (character) => {
    const code = character.charCodeAt(0);
    const data = code.toString(2).padStart(7, '0');
    const ones = [...data].filter((bit) => bit === '1').length;
    const parity = String(ones % 2);
    const bits = `0${data}${parity}1`;

    return { character, code, data, parity, bits };
  });
}

export function textToBitStream(text, options) {
  return buildFrames(text, options).map((frame) => frame.bits).join('');
}

export function validateBitStream(bits) {
  if (typeof bits !== 'string' || bits.length === 0) return 'Data kosong.';
  if (!/^[01]+$/.test(bits)) return 'Data mengandung karakter selain 0 dan 1.';
  if (bits.length % FRAME_LENGTH !== 0) {
    return `Panjang bit (${bits.length}) bukan kelipatan ${FRAME_LENGTH}.`;
  }

  for (let offset = 0; offset < bits.length; offset += FRAME_LENGTH) {
    const frame = bits.slice(offset, offset + FRAME_LENGTH);
    const frameNumber = offset / FRAME_LENGTH + 1;
    if (frame[0] !== '0') return `Frame ${frameNumber}: start bit harus 0.`;
    if (frame[9] !== '1') return `Frame ${frameNumber}: stop bit harus 1.`;

    const data = frame.slice(1, 8);
    const ones = [...data].filter((bit) => bit === '1').length;
    if (String(ones % 2) !== frame[8]) return `Frame ${frameNumber}: parity tidak valid.`;
  }
  return null;
}

/** NRZ-I: a data bit of 1 toggles the line; 0 keeps the previous level. */
export function nrziEncode(bits) {
  let level = 1;
  const levels = [];
  for (const bit of bits) {
    if (bit === '1') level = level === 1 ? 0 : 1;
    levels.push(level);
  }
  return levels;
}

export function nrziDecode(levels) {
  if (!Array.isArray(levels) || levels.length === 0) {
    throw new Error('Sinyal kosong.');
  }
  let previousLevel = 1;
  let bits = '';
  for (const level of levels) {
    if (level !== 0 && level !== 1) throw new Error('Level sinyal tidak valid.');
    if (level !== previousLevel) {
      bits += '1';
      previousLevel = level;
    } else {
      bits += '0';
    }
  }

  const problem = validateBitStream(bits);
  if (problem) throw new Error(problem);

  const frames = [];
  for (let offset = 0; offset < bits.length; offset += FRAME_LENGTH) {
    const frame = bits.slice(offset, offset + FRAME_LENGTH);
    frames.push(String.fromCharCode(Number.parseInt(frame.slice(1, 8), 2)));
  }
  return frames.join('');
}

export function decodeBitStream(bits) {
  const problem = validateBitStream(bits);
  if (problem) throw new Error(problem);
  return nrziDecode(nrziEncode(bits));
}

export function summarizeFrames(bits) {
  const problem = validateBitStream(bits);
  if (problem) throw new Error(problem);
  const frames = [];
  for (let offset = 0; offset < bits.length; offset += FRAME_LENGTH) {
    const frame = bits.slice(offset, offset + FRAME_LENGTH);
    const data = frame.slice(1, 8);
    frames.push({
      index: frames.length + 1,
      character: String.fromCharCode(Number.parseInt(data, 2)),
      code: Number.parseInt(data, 2),
      data,
      parity: frame[8],
      bits: frame,
    });
  }
  return frames;
}
