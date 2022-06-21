# aesscr

Use AES-256-GCM + Scrypt to encrypt files.

## Usage

> npm install -g aesscr

CLI:

```sh
aesscr encrypt password file.zip
aesscr decrypt password file.zip.aesscr
```

## Algorithm

- Encryption: AES-256-GCM
- Ciphertext format: `IV + ciphertext + GCM tag`
- KDF: Scrypt, N=2^19, r=8, p=1, dkLen=32, salt=`aes-1234-scr-5678-gcm`
- password is used in KDF is used to derive AES key

## License

MIT License
