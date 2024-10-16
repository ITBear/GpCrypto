/*
 *
 *  RIPEMD160.c : RIPEMD-160 implementation
 *
 * Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
 *
 * ===================================================================
 * The contents of this file are dedicated to the public domain.  To
 * the extent that dedication to the public domain is not available,
 * everyone is granted a worldwide, perpetual, royalty-free,
 * non-exclusive license to exercise all rights associated with the
 * contents of this file for any purpose whatsoever.
 * No rights are reserved.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ===================================================================
 *
 * Country of origin: Canada
 *
 * This implementation (written in C) is based on an implementation the author
 * wrote in Python.
 *
 * This implementation was written with reference to the RIPEMD-160
 * specification, which is available at:
 * http://homes.esat.kuleuven.be/~cosicart/pdf/AB-9601/
 *
 * It is also documented in the _Handbook of Applied Cryptography_, as
 * Algorithm 9.55.  It's on page 30 of the following PDF file:
 * http://www.cacr.math.uwaterloo.ca/hac/about/chap9.pdf
 *
 * The RIPEMD-160 specification doesn't really tell us how to do padding, but
 * since RIPEMD-160 is inspired by MD4, you can use the padding algorithm from
 * RFC 1320.
 *
 * According to http://www.users.zetnet.co.uk/hopwood/crypto/scan/md.html:
 *   "RIPEMD-160 is big-bit-endian, little-byte-endian, and left-justified."
 */

#include <GpCrypto/GpCryptoCore/ExtSources/ripemd160.hpp>
#include <assert.h>
#include <stdint.h>
#include <string.h>

namespace GPlatform {

struct ripemd160_state
{
    u_int_64 length;

    union
    {
        u_int_32 w[16];
        u_int_8  b[64];
    } buf;

    u_int_32        h[5];
    size_t          bufpos;
};

#define RIPEMD160_DIGEST_SIZE 20
#define BLOCK_SIZE 64

/* cyclic left-shift the 32-bit word n left by s bits */
#define ROL(s, n) (((n) << (s)) | ((n) >> (32-(s))))

/* Initial values for the chaining variables.
 * This is just 0123456789ABCDEFFEDCBA9876543210F0E1D2C3 in little-endian. */
static const u_int_32 initial_h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };

/* Ordering of message words.  Based on the permutations rho(i) and pi(i), defined as follows:
 *
 *  rho(i) := { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 }[i]  0 <= i <= 15
 *
 *  pi(i) := 9*i + 5 (mod 16)
 *
 *  Line  |  Round 1  |  Round 2  |  Round 3  |  Round 4  |  Round 5
 * -------+-----------+-----------+-----------+-----------+-----------
 *  left  |    id     |    rho    |   rho^2   |   rho^3   |   rho^4
 *  right |    pi     |   rho pi  |  rho^2 pi |  rho^3 pi |  rho^4 pi
 */

/* Left line */
static const u_int_8 RL[5][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },   /* Round 1: id */
    { 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8 },   /* Round 2: rho */
    { 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12 },   /* Round 3: rho^2 */
    { 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2 },   /* Round 4: rho^3 */
    { 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13 }    /* Round 5: rho^4 */
};

/* Right line */
static const u_int_8 RR[5][16] = {
    { 5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12 },   /* Round 1: pi */
    { 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2 },   /* Round 2: rho pi */
    { 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13 },   /* Round 3: rho^2 pi */
    { 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14 },   /* Round 4: rho^3 pi */
    { 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11 }    /* Round 5: rho^4 pi */
};

/*
 * Shifts - Since we don't actually re-order the message words according to
 * the permutations above (we could, but it would be slower), these tables
 * come with the permutations pre-applied.
 */

/* Shifts, left line */
static const u_int_8 SL[5][16] = {
    { 11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8 }, /* Round 1 */
    { 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12 }, /* Round 2 */
    { 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5 }, /* Round 3 */
    { 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12 }, /* Round 4 */
    { 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6 }  /* Round 5 */
};

/* Shifts, right line */
static const u_int_8 SR[5][16] = {
    { 8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6 }, /* Round 1 */
    { 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11 }, /* Round 2 */
    { 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5 }, /* Round 3 */
    { 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8 }, /* Round 4 */
    { 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11 }  /* Round 5 */
};

/* Boolean functions */

#define F1(x, y, z) ((x) ^ (y) ^ (z))
#define F2(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define F3(x, y, z) (((x) | ~(y)) ^ (z))
#define F4(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define F5(x, y, z) ((x) ^ ((y) | ~(z)))

/* Round constants, left line */
static const u_int_32 KL[5] = {
    0x00000000u,    /* Round 1: 0 */
    0x5A827999u,    /* Round 2: floor(2**30 * sqrt(2)) */
    0x6ED9EBA1u,    /* Round 3: floor(2**30 * sqrt(3)) */
    0x8F1BBCDCu,    /* Round 4: floor(2**30 * sqrt(5)) */
    0xA953FD4Eu     /* Round 5: floor(2**30 * sqrt(7)) */
};

/* Round constants, right line */
static const u_int_32 KR[5] = {
    0x50A28BE6u,    /* Round 1: floor(2**30 * cubert(2)) */
    0x5C4DD124u,    /* Round 2: floor(2**30 * cubert(3)) */
    0x6D703EF3u,    /* Round 3: floor(2**30 * cubert(5)) */
    0x7A6D76E9u,    /* Round 4: floor(2**30 * cubert(7)) */
    0x00000000u     /* Round 5: 0 */
};

void ripemd160_init(ripemd160_state& aState)
{
    std::memcpy(aState.h, initial_h, RIPEMD160_DIGEST_SIZE);
    std::memset(&aState.buf, 0, sizeof(aState.buf));

    aState.length = 0;
    aState.bufpos = 0;
}

#ifdef PCT_BIG_ENDIAN
static __inline void byteswap32(u_int_32 *v)
{
    union { u_int_32 w; u_int_8 b[4]; } x, y;

    x.w = *v;
    y.b[0] = x.b[3];
    y.b[1] = x.b[2];
    y.b[2] = x.b[1];
    y.b[3] = x.b[0];
    *v = y.w;

    /* Wipe temporary variables */
    x.w = y.w = 0;
}
#endif//#ifdef PCT_BIG_ENDIAN

#ifdef PCT_BIG_ENDIAN
static __inline void byteswap_digest(u_int_32 *p)
{
    unsigned int i;

    for (i = 0; i < 4; i++) {
        byteswap32(p++);
        byteswap32(p++);
        byteswap32(p++);
        byteswap32(p++);
    }
}
#endif//#ifdef PCT_BIG_ENDIAN

/* The RIPEMD160 compression function.  Operates on aState.buf */
static void ripemd160_compress(ripemd160_state& aState)
{
    u_int_8 w, round;
    u_int_32 T;
    u_int_32 AL, BL, CL, DL, EL;    /* left line */
    u_int_32 AR, BR, CR, DR, ER;    /* right line */

    /* Sanity check */
    assert(aState.bufpos == 64);

    /* Byte-swap the buffer if we're on a big-endian machine */
#ifdef PCT_BIG_ENDIAN
    byteswap_digest(aState.buf.w);
#endif

    /* Load the left and right lines with the initial state */
    AL = AR = aState.h[0];
    BL = BR = aState.h[1];
    CL = CR = aState.h[2];
    DL = DR = aState.h[3];
    EL = ER = aState.h[4];

    /* Round 1 */
    round = 0;
    for (w = 0; w < 16; w++) { /* left line */
        T = ROL(SL[round][w], AL + F1(BL, CL, DL) + aState.buf.w[RL[round][w]] + KL[round]) + EL;
        AL = EL; EL = DL; DL = ROL(10, CL); CL = BL; BL = T;
    }
    for (w = 0; w < 16; w++) { /* right line */
        T = ROL(SR[round][w], AR + F5(BR, CR, DR) + aState.buf.w[RR[round][w]] + KR[round]) + ER;
        AR = ER; ER = DR; DR = ROL(10, CR); CR = BR; BR = T;
    }

    /* Round 2 */
    round++;
    for (w = 0; w < 16; w++) { /* left line */
        T = ROL(SL[round][w], AL + F2(BL, CL, DL) + aState.buf.w[RL[round][w]] + KL[round]) + EL;
        AL = EL; EL = DL; DL = ROL(10, CL); CL = BL; BL = T;
    }
    for (w = 0; w < 16; w++) { /* right line */
        T = ROL(SR[round][w], AR + F4(BR, CR, DR) + aState.buf.w[RR[round][w]] + KR[round]) + ER;
        AR = ER; ER = DR; DR = ROL(10, CR); CR = BR; BR = T;
    }

    /* Round 3 */
    round++;
    for (w = 0; w < 16; w++) { /* left line */
        T = ROL(SL[round][w], AL + F3(BL, CL, DL) + aState.buf.w[RL[round][w]] + KL[round]) + EL;
        AL = EL; EL = DL; DL = ROL(10, CL); CL = BL; BL = T;
    }
    for (w = 0; w < 16; w++) { /* right line */
        T = ROL(SR[round][w], AR + F3(BR, CR, DR) + aState.buf.w[RR[round][w]] + KR[round]) + ER;
        AR = ER; ER = DR; DR = ROL(10, CR); CR = BR; BR = T;
    }

    /* Round 4 */
    round++;
    for (w = 0; w < 16; w++) { /* left line */
        T = ROL(SL[round][w], AL + F4(BL, CL, DL) + aState.buf.w[RL[round][w]] + KL[round]) + EL;
        AL = EL; EL = DL; DL = ROL(10, CL); CL = BL; BL = T;
    }
    for (w = 0; w < 16; w++) { /* right line */
        T = ROL(SR[round][w], AR + F2(BR, CR, DR) + aState.buf.w[RR[round][w]] + KR[round]) + ER;
        AR = ER; ER = DR; DR = ROL(10, CR); CR = BR; BR = T;
    }

    /* Round 5 */
    round++;
    for (w = 0; w < 16; w++) { /* left line */
        T = ROL(SL[round][w], AL + F5(BL, CL, DL) + aState.buf.w[RL[round][w]] + KL[round]) + EL;
        AL = EL; EL = DL; DL = ROL(10, CL); CL = BL; BL = T;
    }
    for (w = 0; w < 16; w++) { /* right line */
        T = ROL(SR[round][w], AR + F1(BR, CR, DR) + aState.buf.w[RR[round][w]] + KR[round]) + ER;
        AR = ER; ER = DR; DR = ROL(10, CR); CR = BR; BR = T;
    }

    /* Final mixing stage */
    T = aState.h[1] + CL + DR;
    aState.h[1] = aState.h[2] + DL + ER;
    aState.h[2] = aState.h[3] + EL + AR;
    aState.h[3] = aState.h[4] + AL + BR;
    aState.h[4] = aState.h[0] + BL + CR;
    aState.h[0] = T;

    /* Clear the buffer and wipe the temporary variables */
    T = AL = BL = CL = DL = EL = AR = BR = CR = DR = ER = 0;
    std::memset(&aState.buf, 0, sizeof(aState.buf));
    aState.bufpos = 0;
}

void ripemd160_process
(
    ripemd160_state&    aState,
    GpSpanByteR     aData
)
{
    size_t bytes_needed = 0;
    size_t lengthLeft   = aData.Count();

    /* We never leave a full buffer */
    THROW_COND_GP
    (
        aState.bufpos < 64,
        "Buffer ptr is out of range"_sv
    );

    while (lengthLeft > 0)
    {
        /* Figure out how many bytes we need to fill the internal buffer. */
        bytes_needed = 64 - aState.bufpos;

        if (lengthLeft >= bytes_needed)
        {
            /* We have enough bytes, so copy them into the internal buffer and run
             * the compression function. */
            std::memcpy(&aState.buf.b[aState.bufpos], aData.Ptr(), bytes_needed);
            aState.bufpos += bytes_needed;
            aState.length += bytes_needed << 3;    /* length is in bits */
            aData.OffsetAdd(bytes_needed);
            ripemd160_compress(aState);
            lengthLeft -= bytes_needed;
            continue;
        }

        /* We do not have enough bytes to fill the internal buffer.
         * Copy what's there and return. */
        std::memcpy(&aState.buf.b[aState.bufpos], aData.Ptr(), lengthLeft);
        aState.bufpos += lengthLeft;
        aState.length += lengthLeft << 3;    /* length is in bits */
        return;
    }
}

void    ripemd160_done
(
    ripemd160_state&    aState,
    GpSpanByteRW        aResOut
)
{
    THROW_COND_GP
    (
        aResOut.Count() >= size_t(RIPEMD160_DIGEST_SIZE),
        "aRes size too small"_sv
    );

    /* Append the padding */
    aState.buf.b[aState.bufpos++] = 0x80;

    if (aState.bufpos > 56)
    {
        aState.bufpos = 64;
        ripemd160_compress(aState);
    }

    /* Append the length */
    aState.buf.w[14] = (u_int_32) (aState.length & 0xFFFFffffu);
    aState.buf.w[15] = (u_int_32) ((aState.length >> 32) & 0xFFFFffffu);
#ifdef PCT_BIG_ENDIAN
    byteswap32(&aState.buf.w[14]);
    byteswap32(&aState.buf.w[15]);
#endif
    aState.bufpos = 64;
    ripemd160_compress(aState);

    /* Copy the final state into the output buffer */
#ifdef PCT_BIG_ENDIAN
    byteswap_digest(aState.h);
#endif

    std::memcpy(aResOut.Ptr(), reinterpret_cast<const std::byte*>(&aState.h), size_t(RIPEMD160_DIGEST_SIZE));
}

void Ripemd160
(
    GpSpanByteR     aData,
    GpSpanByteRW    aResOut
)
{
    ripemd160_state md;

    ripemd160_init(md);
    ripemd160_process(md, aData);
    ripemd160_done(md, aResOut);
}

}// namespace GPlatform
