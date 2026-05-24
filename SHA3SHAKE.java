/*
 * TCSS 487 Cryptography Project 1
 * Authors: Rudolf Arakelyan (rudik30) and Linda Miao
 *
 * SHA-3/SHAKE implementation for FIPS 202. This Java implementation was
 * written for the course project and was structurally inspired by Markku-Juhani
 * Saarinen's tiny_sha3 C implementation:
 * https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 */

public class SHA3SHAKE {
    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L,
        0x800000000000808AL, 0x8000000080008000L,
        0x000000000000808BL, 0x0000000080000001L,
        0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008AL, 0x0000000000000088L,
        0x0000000080008009L, 0x000000008000000AL,
        0x000000008000808BL, 0x800000000000008BL,
        0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L,
        0x000000000000800AL, 0x800000008000000AL,
        0x8000000080008081L, 0x8000000000008080L,
        0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] RHO = {
         0,  1, 62, 28, 27,
        36, 44,  6, 55, 20,
         3, 10, 43, 25, 39,
        41, 45, 15, 21,  8,
        18,  2, 61, 56, 14
    };

    private static final byte DOMAIN_SHA3 = 0x06;
    private static final byte DOMAIN_SHAKE = 0x1F;

    private enum Mode {
        UNINITIALIZED,
        ABSORBING,
        SQUEEZING,
        DIGESTING
    }

    private long[] state;
    private int bufLen;
    private int rate;
    private int suffix;
    private Mode mode;
    private byte[] digestCache;

    public SHA3SHAKE() {
        mode = Mode.UNINITIALIZED;
    }

    /**
     * Initialize the SHA-3/SHAKE sponge.
     * The suffix must be one of 224, 256, 384, or 512 for SHA-3, or one of 128 or 256 for SHAKE.
     *
     * @param suffix SHA-3/SHAKE suffix (SHA-3 digest bitlength = suffix, SHAKE sec level = suffix)
     */
    public void init(int suffix) {
        state = new long[25];
        switch (suffix) {
            case 128: rate = 168; break;
            case 224: rate = 144; break;
            case 256: rate = 136; break;
            case 384: rate = 104; break;
            case 512: rate = 72; break;
            default:
                throw new IllegalArgumentException("suffix must be 128, 224, 256, 384, or 512");
        }

        this.suffix = suffix;
        bufLen = 0;
        digestCache = null;
        mode = Mode.ABSORBING;
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param pos initial index to hash from
     * @param len byte count on the buffer
     */
    public void absorb(byte[] data, int pos, int len) {
        requireInitialized("absorb()");
        if (mode != Mode.ABSORBING) {
            throw new IllegalStateException("cannot absorb after squeeze()/digest(); call init() first");
        }
        if (data == null) {
            throw new NullPointerException("data");
        }
        if (pos < 0 || len < 0 || pos + len > data.length) {
            throw new IllegalArgumentException("invalid pos/len for absorb()");
        }

        for (int i = pos; i < pos + len; i++) {
            state[bufLen / 8] ^= (long) (data[i] & 0xFF) << (8 * (bufLen % 8));
            bufLen++;
            if (bufLen == rate) {
                keccakF();
                bufLen = 0;
            }
        }
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     * @param len byte count on the buffer (starting at index 0)
     */
    public void absorb(byte[] data, int len) {
        absorb(data, 0, len);
    }

    /**
     * Update the SHAKE sponge with a byte-oriented data chunk.
     *
     * @param data byte-oriented data buffer
     */
    public void absorb(byte[] data) {
        absorb(data, 0, data.length);
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param out hash value buffer
     * @param len desired number of squeezed bytes
     * @return the out buffer containing the desired hash value
     */
    public byte[] squeeze(byte[] out, int len) {
        requireInitialized("squeeze()");
        if (mode == Mode.DIGESTING) {
            throw new IllegalStateException("cannot call squeeze() after digest(); call init() first");
        }
        if (out == null) {
            throw new NullPointerException("out");
        }
        if (len < 0 || len > out.length) {
            throw new IllegalArgumentException("len must be between 0 and out.length");
        }

        if (mode == Mode.ABSORBING) {
            finalizeAbsorb(selectSqueezeDomainByte());
            mode = Mode.SQUEEZING;
        }

        squeezeInto(out, len);
        return out;
    }

    /**
     * Squeeze a chunk of hashed bytes from the sponge.
     * Call this method as many times as needed to extract the total desired number of bytes.
     *
     * @param len desired number of squeezed bytes
     * @return newly allocated buffer containing the desired hash value
     */
    public byte[] squeeze(int len) {
        if (len < 0) {
            throw new IllegalArgumentException("len must be >= 0");
        }
        return squeeze(new byte[len], len);
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @param out hash value buffer
     * @return the out buffer containing the desired hash value
     */
    public byte[] digest(byte[] out) {
        requireInitialized("digest()");
        if (mode == Mode.SQUEEZING) {
            throw new IllegalStateException("cannot call digest() after squeeze(); call init() first");
        }
        if (suffix == 128) {
            throw new IllegalStateException("digest() is not defined for SHAKE-128; use squeeze()");
        }

        int digestLen = suffix / 8;
        if (out == null) {
            out = new byte[digestLen];
        }
        if (out.length < digestLen) {
            throw new IllegalArgumentException("out buffer is too small for digest");
        }

        if (mode == Mode.ABSORBING) {
            finalizeAbsorb(DOMAIN_SHA3);
            mode = Mode.DIGESTING;
            digestCache = new byte[digestLen];
            squeezeInto(digestCache, digestLen);
        }

        System.arraycopy(digestCache, 0, out, 0, digestLen);
        return out;
    }

    /**
     * Squeeze a whole SHA-3 digest of hashed bytes from the sponge.
     *
     * @return the desired hash value on a newly allocated byte array
     */
    public byte[] digest() {
        return digest(null);
    }

    /**
     * Compute the streamlined SHA-3-<224,256,384,512> on input X.
     *
     * @param suffix desired output length in bits (one of 224, 256, 384, 512)
     * @param X data to be hashed
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHA3(int suffix, byte[] X, byte[] out) {
        if (suffix != 224 && suffix != 256 && suffix != 384 && suffix != 512) {
            throw new IllegalArgumentException("SHA3 suffix must be one of 224, 256, 384, 512");
        }
        int digestLen = suffix / 8;
        if (out == null) {
            out = new byte[digestLen];
        }
        if (out.length < digestLen) {
            throw new IllegalArgumentException("out buffer is too small for SHA3 output");
        }

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        return sponge.digest(out);
    }

    /**
     * Compute the streamlined SHAKE-<128,256> on input X with output bitlength L.
     *
     * @param suffix desired security level (either 128 or 256)
     * @param X data to be hashed
     * @param L desired output length in bits (must be a multiple of 8)
     * @param out hash value buffer (if null, this method allocates it with the required size)
     * @return the out buffer containing the desired hash value.
     */
    public static byte[] SHAKE(int suffix, byte[] X, int L, byte[] out) {
        if (suffix != 128 && suffix != 256) {
            throw new IllegalArgumentException("SHAKE suffix must be 128 or 256");
        }
        if (L < 0 || (L % 8) != 0) {
            throw new IllegalArgumentException("SHAKE output length L must be >= 0 and a multiple of 8");
        }

        int outLen = L / 8;
        if (out == null) {
            out = new byte[outLen];
        }
        if (out.length < outLen) {
            throw new IllegalArgumentException("out buffer is too small for SHAKE output");
        }

        SHA3SHAKE sponge = new SHA3SHAKE();
        sponge.init(suffix);
        sponge.absorb(X);
        return sponge.squeeze(out, outLen);
    }

    private void requireInitialized(String method) {
        if (mode == Mode.UNINITIALIZED) {
            throw new IllegalStateException(method + " requires init() first");
        }
    }

    private byte selectSqueezeDomainByte() {
        return (suffix == 128 || suffix == 256) ? DOMAIN_SHAKE : DOMAIN_SHA3;
    }

    private void finalizeAbsorb(byte domainByte) {
        state[bufLen / 8] ^= (long) (domainByte & 0xFF) << (8 * (bufLen % 8));
        state[(rate - 1) / 8] ^= 0x80L << (8 * ((rate - 1) % 8));
        keccakF();
        bufLen = 0;
    }

    private void squeezeInto(byte[] out, int len) {
        for (int i = 0; i < len; i++) {
            if (bufLen == rate) {
                keccakF();
                bufLen = 0;
            }
            out[i] = (byte) (state[bufLen / 8] >>> (8 * (bufLen % 8)));
            bufLen++;
        }
    }

    private void keccakF() {
        long[] A = state;
        long[] B = new long[25];
        long[] C = new long[5];
        long[] D = new long[5];

        for (int round = 0; round < 24; round++) {
            for (int x = 0; x < 5; x++) {
                C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
            }

            for (int x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ rotL(C[(x + 1) % 5], 1);
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    A[x + 5 * y] ^= D[x];
                }
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int src = x + 5 * y;
                    B[y + 5 * ((2 * x + 3 * y) % 5)] = rotL(A[src], RHO[src]);
                }
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    A[x + 5 * y] = B[x + 5 * y]
                        ^ (~B[(x + 1) % 5 + 5 * y] & B[(x + 2) % 5 + 5 * y]);
                }
            }

            A[0] ^= RC[round];
        }
    }

    private static long rotL(long x, int n) {
        return (x << n) | (x >>> (64 - n));
    }
}
