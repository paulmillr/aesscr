# aesscr

Use AES-256-GCM + Scrypt to encrypt files.

## Usage

> npm install -g aesscr

CLI:

```sh
aesscr encrypt file.zip PASSWORD
# will create file.zip.aesscr
aesscr decrypt file.zip.aesscr PASSWORD
# will create file.zip

# PASSWORD must be 14 or more characters
# PASSWORD can be also supplied in ENV variable:
export AES_PASSWORD='abcdefabcdef1234'
aesscr encrypt file.zip
```

API:

```ts
import { encrypt, decrypt } from 'aesscr';
await encrypt("password101520", Uint8Array.from([5, 10, 11]));
```

## Algorithm

- Encryption: AES-256-GCM
- Ciphertext format: `IV + ciphertext + GCM tag`
- KDF: Scrypt, N=2^19, r=8, p=1, dkLen=32, salt=`aes-1234-scr-5678-gcm`
- password is used in KDF is used to derive AES key

## License

MIT License
