/* tslint:disable */
/* eslint-disable */
/**
*/
export function start(): void;
/**
*/
export class SM2 {
  free(): void;
/**
*/
  constructor();
/**
* @returns {any}
*/
  new_keypair(): any;
/**
* @param {Uint8Array} sk
* @returns {Uint8Array}
*/
  pk_from_sk(sk: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} buffer
* @param {Uint8Array} sk
* @param {Uint8Array} pk
* @returns {Uint8Array}
*/
  sign(buffer: Uint8Array, sk: Uint8Array, pk: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} buffer
* @param {Uint8Array} pk
* @param {Uint8Array} signature
* @returns {boolean}
*/
  verify(buffer: Uint8Array, pk: Uint8Array, signature: Uint8Array): boolean;
}
/**
*/
export class SM2Decrypt {
  free(): void;
/**
* @param {number} klen
* @param {Uint8Array} sk
*/
  constructor(klen: number, sk: Uint8Array);
/**
* @param {Uint8Array} buffer
* @returns {Uint8Array}
*/
  decrypt(buffer: Uint8Array): Uint8Array;
}
/**
*/
export class SM2Encrypt {
  free(): void;
/**
* @param {number} klen
* @param {Uint8Array} pk
*/
  constructor(klen: number, pk: Uint8Array);
/**
* @param {Uint8Array} buffer
* @returns {Uint8Array}
*/
  encrypt(buffer: Uint8Array): Uint8Array;
}
/**
*/
export class SM2ExchangeA {
  free(): void;
/**
* @param {number} klen
* @param {string} id_a
* @param {string} id_b
* @param {Uint8Array} pk_a
* @param {Uint8Array} pk_b
* @param {Uint8Array} sk_a
*/
  constructor(klen: number, id_a: string, id_b: string, pk_a: Uint8Array, pk_b: Uint8Array, sk_a: Uint8Array);
/**
* @returns {Uint8Array}
*/
  exchange1(): Uint8Array;
/**
* @param {Uint8Array} r_b
* @param {Uint8Array} s_b
* @returns {Uint8Array}
*/
  exchange3(r_b: Uint8Array, s_b: Uint8Array): Uint8Array;
/**
* @returns {Uint8Array}
*/
  get_key(): Uint8Array;
}
/**
*/
export class SM2ExchangeB {
  free(): void;
/**
* @param {number} klen
* @param {string} id_a
* @param {string} id_b
* @param {Uint8Array} pk_a
* @param {Uint8Array} pk_b
* @param {Uint8Array} sk_b
*/
  constructor(klen: number, id_a: string, id_b: string, pk_a: Uint8Array, pk_b: Uint8Array, sk_b: Uint8Array);
/**
* @param {Uint8Array} r_a
* @returns {any}
*/
  exchange2(r_a: Uint8Array): any;
/**
* @param {Uint8Array} r_a
* @param {Uint8Array} s_a
* @returns {boolean}
*/
  exchange4(r_a: Uint8Array, s_a: Uint8Array): boolean;
/**
* @returns {Uint8Array}
*/
  get_key(): Uint8Array;
}
/**
*/
export class SM3 {
  free(): void;
/**
* @param {Uint8Array} buffer
*/
  constructor(buffer: Uint8Array);
/**
* @returns {Uint8Array}
*/
  get_hash(): Uint8Array;
}
/**
*/
export class SM4 {
  free(): void;
/**
* @param {Uint8Array} key
*/
  constructor(key: Uint8Array);
/**
* @param {Uint8Array} plain_buffer
* @returns {Uint8Array}
*/
  encrypt(plain_buffer: Uint8Array): Uint8Array;
/**
* @param {Uint8Array} cipher_buffer
* @returns {Uint8Array}
*/
  decrypt(cipher_buffer: Uint8Array): Uint8Array;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_sm4_free: (a: number) => void;
  readonly sm4_new: (a: number, b: number) => number;
  readonly sm4_encrypt: (a: number, b: number, c: number, d: number) => void;
  readonly sm4_decrypt: (a: number, b: number, c: number, d: number) => void;
  readonly __wbg_sm2_free: (a: number) => void;
  readonly sm2_new: () => number;
  readonly sm2_new_keypair: (a: number) => number;
  readonly sm2_pk_from_sk: (a: number, b: number, c: number, d: number) => void;
  readonly sm2_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => void;
  readonly sm2_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => number;
  readonly __wbg_sm2encrypt_free: (a: number) => void;
  readonly sm2encrypt_new: (a: number, b: number, c: number) => number;
  readonly sm2encrypt_encrypt: (a: number, b: number, c: number, d: number) => void;
  readonly __wbg_sm2decrypt_free: (a: number) => void;
  readonly sm2decrypt_new: (a: number, b: number, c: number) => number;
  readonly sm2decrypt_decrypt: (a: number, b: number, c: number, d: number) => void;
  readonly __wbg_sm2exchangea_free: (a: number) => void;
  readonly sm2exchangea_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => number;
  readonly sm2exchangea_exchange1: (a: number, b: number) => void;
  readonly sm2exchangea_exchange3: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
  readonly sm2exchangea_get_key: (a: number, b: number) => void;
  readonly __wbg_sm2exchangeb_free: (a: number) => void;
  readonly sm2exchangeb_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => number;
  readonly sm2exchangeb_exchange2: (a: number, b: number, c: number) => number;
  readonly sm2exchangeb_exchange4: (a: number, b: number, c: number, d: number, e: number) => number;
  readonly sm2exchangeb_get_key: (a: number, b: number) => void;
  readonly start: () => void;
  readonly __wbg_sm3_free: (a: number) => void;
  readonly sm3_new: (a: number, b: number) => number;
  readonly sm3_get_hash: (a: number, b: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
