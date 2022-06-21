#!/usr/bin/env node

const { readFileSync, writeFileSync } = require('fs');
const { sha256 } = require('@noble/hashes/sha256');
const { scrypt } = require('@noble/hashes/scrypt');
const { bytesToHex } = require('@noble/hashes/utils');
const aes = require('micro-aes-gcm');

const EXTENSION = '.aesscr';
const EXTENSION_RE = /\.aesscr$/;

function scr(password) {
  return scrypt(password, 'aes-1234-scr-5678-gcm', { N: 2 ** 19, r: 8, p: 1, dkLen: 32 });
}
function usage() {
  console.log(`usage:
  aesscr encrypt file.zip PASSWORD
  aesscr decrypt file.zip.aesscr PASSWORD
  PASSWORD must be 14 or more characters
  PASSWORD can be also supplied in ENV variable:
  AES_PASSWORD='abcdefabcdef1234' aesscr encrypt file.zip
`);
  process.exit(1);
}

async function encrypt(password, filePath) {
  const plaintext = Uint8Array.from(readFileSync(filePath));
  const checksum = bytesToHex(sha256(plaintext));
  console.log(`plaintext sha256 checksum: ${checksum}`)
  const encrypted = await aes.encrypt(scr(password), plaintext);
  const encFilePath = `${filePath}.aesscr`;
  writeFileSync(encFilePath, encrypted);
  console.log(`saved to ${encFilePath}`);
}

async function decrypt(password, filePath) {
  if (!filePath.endsWith(EXTENSION)) {
    throw new Error('filename must end with .aesscr: abcdef.zip.aesscr');
  }
  const decFilePath = `${filePath.replace(EXTENSION_RE, '')}`;
  const plaintext = await aes.decrypt(scr(password), Uint8Array.from(readFileSync(filePath)));
  console.log(`plaintext sha256 checksum: ${bytesToHex(sha256(plaintext))}`)
  writeFileSync(`${decFilePath}`, plaintext);
  console.log(`saved to ${decFilePath}`);
}

async function main() {
  const action = process.argv[2];
  const filePath = process.argv[3];
  const password = process.argv[4] || process.env.AES_PASSWORD;
  if (typeof password !== 'string' || password.length < 14) usage();
  if (typeof filePath !== 'string') usage();

  if (action === 'encrypt') {
    await encrypt(password, filePath);
  } else if (action === 'decrypt') {
    await decrypt(password, filePath);
  } else {
    usage();
  }
}

main();
