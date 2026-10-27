// aes_scan.c — AES-NI 加速的 32 字节密钥扫描器（AES-256）
// 编译：gcc -O3 -maes -shared -o aes_scan.dll aes_scan.c
#include <emmintrin.h>
#include <wmmintrin.h>
#include <stdint.h>
#include <string.h>

static inline __m128i as1(__m128i a, __m128i g) {   // word3 (0xff) + RotWord
    __m128i m = _mm_shuffle_epi32(g, 0xff);
    __m128i t = _mm_slli_si128(a, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    return _mm_xor_si128(a, m);
}
static inline __m128i as2(__m128i a, __m128i g) {   // word2 (0xaa)，无 RotWord
    __m128i m = _mm_shuffle_epi32(g, 0xaa);
    __m128i t = _mm_slli_si128(a, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    t = _mm_slli_si128(t, 4);
    a = _mm_xor_si128(a, t);
    return _mm_xor_si128(a, m);
}

static inline void expand256(const uint8_t *k, __m128i rk[15]) {
    __m128i k1 = _mm_loadu_si128((const __m128i *)k);
    __m128i k2 = _mm_loadu_si128((const __m128i *)(k + 16));
    rk[0] = k1; rk[1] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x01)); rk[2] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[3] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x02)); rk[4] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[5] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x04)); rk[6] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[7] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x08)); rk[8] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[9] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x10)); rk[10] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[11] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x20)); rk[12] = k1;
    k2 = as2(k2, _mm_aeskeygenassist_si128(k1, 0x00)); rk[13] = k2;
    k1 = as1(k1, _mm_aeskeygenassist_si128(k2, 0x40)); rk[14] = k1;
}

static inline __m128i encrypt_block(__m128i b, const __m128i rk[15]) {
    b = _mm_xor_si128(b, rk[0]);
    for (int i = 1; i < 14; i++) b = _mm_aesenc_si128(b, rk[i]);
    return _mm_aesenclast_si128(b, rk[14]);
}

int scan_buf(const uint8_t *buf, size_t len, int stride,
             const uint8_t *j0, const uint8_t *ct0,
             uint64_t *hit_offsets, uint8_t *hit_keys, int max_hits) {
    int hits = 0;
    if (len < 40) return 0;
    const __m128i in = _mm_loadu_si128((const __m128i *)j0);
    const __m128i target = _mm_loadu_si128((const __m128i *)ct0);
    const size_t last = len - 32;
    for (size_t i = 0; i < last; i += stride) {
        const uint8_t *k = buf + i;
        uint32_t zeroish = 0;
        for (int z = 0; z < 32; z += 4) {
            uint32_t v;
            memcpy(&v, k + z, 4);
            if (v == 0) zeroish++;
        }
        if (zeroish > 4) continue;
        __m128i rk[15];
        expand256(k, rk);
        __m128i pt = _mm_xor_si128(encrypt_block(in, rk), target);
        uint8_t tmp[16];
        _mm_storeu_si128((__m128i *)tmp, pt);
        int ok = 1;
        for (int j = 0; j < 16; j++) {
            uint8_t c = tmp[j];
            if (!((c >= 9 && c <= 13) || (c >= 32 && c <= 126))) { ok = 0; break; }
        }
        if (!ok) continue;
        if (hits < max_hits) {
            hit_offsets[hits] = (uint64_t)i;
            memcpy(hit_keys + (size_t)hits * 32, k, 32);
        }
        hits++;
    }
    return hits;
}
