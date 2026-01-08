/**
 * UTF-8 encoding support list
 *
 * <p>Only UTF-8 related aliases are supported</p>
 */
const utf8Encodings: string[] = [
    'utf8',
    'utf-8',
    'unicode-1-1-utf-8',
]

/**
 * TextEncoder implementation
 *
 * <p>Equivalent to Web TextEncoder, only UTF-8 is supported</p>
 */
export class TextEncoder {

    encoding: 'utf-8'

    /**
     * Constructor
     *
     * @param encoding Encoding type, only utf-8 is supported
     */
    constructor(encoding?: string | null) {
        if (
            encoding != null &&
            utf8Encodings.indexOf(encoding) < 0
        ) {
            throw new RangeError('Invalid encoding type. Only utf-8 is supported')
        }

        this.encoding = 'utf-8'
    }

    /**
     * Encode a string into Uint8Array
     *
     * @param str String to encode
     * @returns UTF-8 byte array
     */
    encode(str: string): Uint8Array {
        if (typeof str !== 'string') {
            throw new TypeError('passed argument must be of type string')
        }

        const binstr: string = unescape(encodeURIComponent(str))
        const arr: Uint8Array = new Uint8Array(binstr.length)

        for (let i = 0; i < binstr.length; i++) {
            arr[i] = binstr.charCodeAt(i)
        }

        return arr
    }
}

/**
 * TextDecoder implementation
 *
 * <p>Equivalent to Web TextDecoder, only UTF-8 is supported</p>
 */
export class TextDecoder {

    encoding: 'utf-8'

    /**
     * Constructor
     *
     * @param encoding Encoding type, only utf-8 is supported
     */
    constructor(encoding?: string | null) {
        if (
            encoding != null &&
            utf8Encodings.indexOf(encoding) < 0
        ) {
            throw new RangeError('Invalid encoding type. Only utf-8 is supported')
        }

        this.encoding = 'utf-8'
    }

    /**
     * Decode Uint8Array or ArrayBuffer to string
     *
     * @param view ArrayBufferView to decode
     * @param options Optional { stream: boolean }
     * @returns Decoded string
     */
    decode(
        view?: ArrayBufferView,
        options?: { stream?: boolean }
    ): string {
        if (typeof view === 'undefined') {
            return ''
        }

        const stream: boolean = options?.stream ?? false

        if (typeof stream !== 'boolean') {
            throw new TypeError('stream option must be boolean')
        }

        if (!ArrayBuffer.isView(view)) {
            throw new TypeError('passed argument must be an array buffer view')
        }

        const arr: Uint8Array = new Uint8Array(
            view.buffer,
            view.byteOffset,
            view.byteLength
        )

        let str: string = ''
        for (let i = 0; i < arr.length; i++) {
            str += String.fromCharCode(arr[i])
        }

        return decodeURIComponent(escape(str))
    }
}
