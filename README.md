# `libsm-js-miniprogram`

A WXWebAssembly Library of SM2, SM3 and SM4. Based on [`libsm`](https://github.com/citahub/libsm).

## Importing and Initializing

```javascript
// Import the WASM module and algorithm classes
import __wbg_init, { SM3, SM2Decrypt, SM4, SM2Encrypt } from '../libsm-miniprogram/libsm_js_miniprogram';

// Initialize the WASM module
// Note: '/static/libsm_js_miniprogram_bg.wasm' is the absolute path to the WASM file in your Mini Program
__wbg_init("/static/libsm_js_miniprogram_bg.wasm").then(() => {
    console.log("WASM module initialized successfully");
});
```

## TextEncoder / TextDecoder in Mini Programs

WeChat Mini Programs **do not provide global `TextEncoder` or `TextDecoder`**.  
This library includes a simple implementation that you can import:

```javascript
import { TextEncoder, TextDecoder } from "../libsm-miniprogram/text_encoder";

// Example usage
const encoder = new TextEncoder();
const data = encoder.encode("Hello, Mini Program!");

const decoder = new TextDecoder();
const message = decoder.decode(data);

console.log(message); // "Hello, Mini Program!"
```

## Example

```javascript
import __wbg_init, { SM3, SM2Encrypt, SM2Decrypt, SM4 } from '../libsm-miniprogram/libsm_js_miniprogram';
import { TextEncoder, TextDecoder } from "../libsm-miniprogram/text_encoder";

/**
 * SM3 Hash Example
 *
 * <p>Compute the SM3 hash of a string</p>
 */
function sm3HashExample(messageStr) {
    const message = new TextEncoder().encode(messageStr);
    const sm3 = new SM3(message);
    const hash = sm3.get_hash();
    console.log("SM3 Hash:", Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));
}

/**
 * SM2 Encryption/Decryption Example
 *
 * <p>Encrypt and decrypt a message using SM2 with a key pair</p>
 */
async function sm2Example() {
    await __wbg_init("/static/libsm_js_miniprogram_bg.wasm");

    const sk = new Uint8Array(32); // secret key Uint8Array
    const pk = new Uint8Array(65); // public key Uint8Array

    // Encrypt message
    const data = new TextEncoder().encode("Hello SM2!");
    const sm2Encrypt = new SM2Encrypt(32, pk);
    const cipher = sm2Encrypt.encrypt(data);

    // Decrypt message
    const sm2Decrypt = new SM2Decrypt(32, sk);
    const plain = sm2Decrypt.decrypt(cipher);
    console.log("Decrypted message:", new TextDecoder().decode(plain));
}

/**
 * SM4 Symmetric Encryption Example
 *
 * <p>Encrypt and decrypt a message using SM4 symmetric key</p>
 */
function sm4Example() {
    const key = new Uint8Array(16); // 16-byte symmetric key
    const sm4 = new SM4(key);

    const plaintext = new TextEncoder().encode("Hello SM4!");
    const ciphertext = sm4.encrypt(plaintext);
    const decrypted = sm4.decrypt(ciphertext);

    console.log("Decrypted message:", new TextDecoder().decode(decrypted));
}

// Example calls
sm3HashExample("Hello, world!");
sm2Example();
sm4Example();
```



## Environment and Tool Versions

The following tools and versions were used to build and run this project:

| Tool / Library          | Version / Description                  |
| ----------------------- | -------------------------------------- |
| WeChat Mini Program SDK | 3.13.x                                 |
| Rust                    | 1.56.0                                 |
| wasm-bindgen            | 0.2.63, with `serde-serialize` feature |
| wasm-pack               | 0.10.3                                 |
| TypeScript              | >= 4.5                                 |
| libsm-js (fork)         | Customized for Mini Program support    |

> Notes:
> - This project is designed specifically for WeChat Mini Programs.
> - Custom `TextEncoder`/`TextDecoder` are provided because Mini Programs do not expose global objects.
> - WASM files must be placed in the Mini Program root `/static/` folder.

# libsm-js-miniprogram

This project is a fork of [libsm-js](https://github.com/Lifeni/libsm-js).

## Modifications in this fork

- Added compatibility for WeChat Mini Program
- Manually maintained JS glue layer instead of auto-generated wasm-bindgen
- Pinned Rust toolchain to 1.56.0 and wasm-bindgen to 0.2.63
- Modified libsm sub-crate to integrate directly into root repository
- Replaced original random number generation with JavaScript `Math.random()` for SM4 IV and key generation

## License

This project is licensed under either of

- Apache License, Version 2.0, (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
