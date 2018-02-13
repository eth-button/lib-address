import CryptoJS from "crypto-js";
import { isValidPrivate, toBuffer } from "ethereumjs-util";

const SHA256 = CryptoJS.algo.SHA256;
const Hex = CryptoJS.enc.Hex;
const WordArray = CryptoJS.lib.WordArray;
const CTR = CryptoJS.mode.CTR;
const NoPadding = CryptoJS.pad.NoPadding;
const AES = CryptoJS.AES;
const PBKDF2 = CryptoJS.PBKDF2;
const SHA3 = CryptoJS.SHA3;

const WORD_SIZE = 4;
const CIPHER = "aes-128-ctr";
const DIGEST = "hmac-sha256";
const KDF = "pbkdf2";
const KEY_BYTES = 32;
const DERIVED_KEY_BYTES = 32;
const SALT_BYTES = 32;
const IV_BYTES = 16;
const MAX_ITERATIONS = 1000000;

function generateDerivedKey(password, salt, iterations) {
  return PBKDF2(password, salt, {
    keySize: DERIVED_KEY_BYTES / WORD_SIZE,
    hasher: SHA256,
    iterations: iterations
  });
}

function sliceWordArray(wordArray, start, end) {
  start = start || 0;
  end = end || wordArray.words.length;
  const newArray = wordArray.clone();
  newArray.words = newArray.words.slice(start, end);
  newArray.sigBytes = (end - start) * 4;
  return newArray;
}

export function generatePrivateKey() {
  let privateKey;
  do {
    privateKey = toBuffer("0x" + WordArray.random(KEY_BYTES).toString());
  } while (!isValidPrivate(privateKey));

  return privateKey;
}

export function encryptPrivateKey(privateKey, password) {
  const iv = WordArray.random(IV_BYTES);
  const salt = WordArray.random(SALT_BYTES);
  const iterations = Math.floor(Math.random() * MAX_ITERATIONS);
  const key = generateDerivedKey(password, salt, iterations);
  const cipher = AES.encrypt(
    Hex.parse(privateKey.toString("hex")),
    sliceWordArray(key, 0, 4),
    {
      iv: iv,
      mode: CTR,
      padding: NoPadding
    }
  );
  const mac = SHA3(sliceWordArray(key, 4, 8).concat(cipher.ciphertext), {
    outputLength: 256
  });

  return {
    kdf: KDF,
    kdfparams: {
      c: iterations,
      dklen: DERIVED_KEY_BYTES,
      prf: DIGEST,
      salt: salt.toString()
    },
    cipher: CIPHER,
    ciphertext: cipher.ciphertext.toString(),
    cipherparams: {
      iv: iv.toString()
    },
    mac: mac.toString()
  };
}
