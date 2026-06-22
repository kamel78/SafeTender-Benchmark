/* tslint:disable */
/* eslint-disable */

export class Combiner {
    free(): void;
    [Symbol.dispose](): void;
    combine_shares(shares: any): string;
    get_last_timing_ms(): number;
    constructor(js_users_list: any, threshold: number);
}

export class DecryptionResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly plaintext: Uint8Array;
    readonly time_ms: number;
}

export class EicCrypt {
    free(): void;
    [Symbol.dispose](): void;
    decrypt(secrete_key: string, ciphertext: string): string;
    decrypt_pdf(secret_key_b64: string, input_bytes: Uint8Array): DecryptionResult;
    encrypt(public_key: string, plaintext: string): string;
    encrypt_pdf(public_key_str: string, input_bytes: Uint8Array): EncryptionResult;
    constructor();
}

export class EncryptionResult {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly ciphertext: Uint8Array;
    time_ms: number;
}

export class PubKeyAdder {
    free(): void;
    [Symbol.dispose](): void;
    add(new_point: string): void;
    get_pubkey(): string;
    constructor();
}

export class WShamirUser {
    free(): void;
    [Symbol.dispose](): void;
    generate_secret(): void;
    get_last_timing_ms(): number;
    get_partial_pubkey(): string;
    get_partial_secrete(): string;
    get_secret_part_for_user(in_user: string): string;
    get_share(): string;
    constructor(js_users_list: any, username: string, threshold: number);
    static new_from_serialized(json_string: string): WShamirUser;
    serialize(): string;
    update_share(in_user: string, in_share_part: string): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_combiner_free: (a: number, b: number) => void;
    readonly __wbg_decryptionresult_free: (a: number, b: number) => void;
    readonly __wbg_eiccrypt_free: (a: number, b: number) => void;
    readonly __wbg_encryptionresult_free: (a: number, b: number) => void;
    readonly __wbg_get_encryptionresult_time_ms: (a: number) => number;
    readonly __wbg_pubkeyadder_free: (a: number, b: number) => void;
    readonly __wbg_set_encryptionresult_time_ms: (a: number, b: number) => void;
    readonly __wbg_wshamiruser_free: (a: number, b: number) => void;
    readonly combiner_combine_shares: (a: number, b: any) => [number, number];
    readonly combiner_get_last_timing_ms: (a: number) => number;
    readonly combiner_new: (a: any, b: number) => number;
    readonly decryptionresult_plaintext: (a: number) => [number, number];
    readonly eiccrypt_decrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly eiccrypt_decrypt_pdf: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly eiccrypt_encrypt: (a: number, b: number, c: number, d: number, e: number) => [number, number];
    readonly eiccrypt_encrypt_pdf: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly eiccrypt_new: () => number;
    readonly encryptionresult_ciphertext: (a: number) => [number, number];
    readonly pubkeyadder_add: (a: number, b: number, c: number) => void;
    readonly pubkeyadder_get_pubkey: (a: number) => [number, number];
    readonly pubkeyadder_new: () => number;
    readonly wshamiruser_generate_secret: (a: number) => void;
    readonly wshamiruser_get_last_timing_ms: (a: number) => number;
    readonly wshamiruser_get_partial_pubkey: (a: number) => [number, number];
    readonly wshamiruser_get_partial_secrete: (a: number) => [number, number];
    readonly wshamiruser_get_secret_part_for_user: (a: number, b: number, c: number) => [number, number];
    readonly wshamiruser_get_share: (a: number) => [number, number];
    readonly wshamiruser_new: (a: any, b: number, c: number, d: number) => number;
    readonly wshamiruser_new_from_serialized: (a: number, b: number) => number;
    readonly wshamiruser_serialize: (a: number) => [number, number];
    readonly wshamiruser_update_share: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly decryptionresult_time_ms: (a: number) => number;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
