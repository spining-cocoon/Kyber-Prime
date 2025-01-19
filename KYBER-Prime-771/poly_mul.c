#include "poly_mul.h"
#include <stdint.h>
#include <string.h>
#include "reduce.h"
#include "params.h"

#define N_MUL 272
#define N_RES (N_MUL << 1)
#define N_SB (N_MUL >> 2)
#define N_SB_RES (2*N_SB-1)

#define fqmul_mont(x,y) fqmul(mont2,fqmul(x,y))

#define KARATSUBA_N 68

static void karatsuba_simple_lazy(const int16_t *a_1, const int16_t *b_1, int16_t *result_final) {
    int16_t d01[KARATSUBA_N / 2 - 1] = {0};
    int16_t d0123[KARATSUBA_N / 2 - 1] = {0};
    int16_t d23[KARATSUBA_N / 2 - 1] = {0};
    int16_t result_d01[KARATSUBA_N - 1] = {0};

    int32_t i, j;

    memset(result_final, 0, (2 * KARATSUBA_N - 1)*sizeof(int16_t));

    int16_t acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8, acc9, acc10;


    for (i = 0; i < KARATSUBA_N / 4; i++) { 
        acc1 = a_1[i]; 
        acc2 = a_1[i + KARATSUBA_N / 4]; 
        acc3 = a_1[i + 2 * KARATSUBA_N / 4]; 
        acc4 = a_1[i + 3 * KARATSUBA_N / 4]; 
        for (j = 0; j < KARATSUBA_N / 4; j++) {

            acc5 = b_1[j]; 
            acc6 = b_1[j + KARATSUBA_N / 4]; 

            result_final[i + j + 0 * KARATSUBA_N / 4] = reduce32to16(result_final[i + j + 0 * KARATSUBA_N / 4] + (int32_t)acc1 * acc5); 
            result_final[i + j + 2 * KARATSUBA_N / 4] = reduce32to16(result_final[i + j + 2 * KARATSUBA_N / 4] + (int32_t)acc2 * acc6); 

            acc7 = acc5 + acc6; 
            acc8 = acc1 + acc2; 
            d01[i + j] = reduce32to16(d01[i + j] + (int32_t)acc7 * acc8);
            //--------------------------------------------------------

            acc7 = b_1[j + 2 * KARATSUBA_N / 4]; 
            acc8 = b_1[j + 3 * KARATSUBA_N / 4]; 

            result_final[i + j + 4 * KARATSUBA_N / 4] = reduce32to16(result_final[i + j + 4 * KARATSUBA_N / 4] + (int32_t)acc7 * acc3);
            result_final[i + j + 6 * KARATSUBA_N / 4] = reduce32to16(result_final[i + j + 6 * KARATSUBA_N / 4] + (int32_t)acc8 * acc4);

            acc9 = acc3 + acc4;
            acc10 = acc7 + acc8;
            d23[i + j] = reduce32to16(d23[i + j] + (int32_t)acc9 * acc10);
            //--------------------------------------------------------

            acc5 = acc5 + acc7; 
            acc7 = acc1 + acc3; 
            result_d01[i + j + 0 * KARATSUBA_N / 4] = reduce32to16(result_d01[i + j + 0 * KARATSUBA_N / 4] + (int32_t)acc5 * acc7);

            acc6 = acc6 + acc8; 
            acc8 = acc2 + acc4; 
            result_d01[i + j + 2 * KARATSUBA_N / 4] = reduce32to16(result_d01[i + j + 2 * KARATSUBA_N / 4] + (int32_t)acc6 * acc8); 

            acc5 = acc5 + acc6;
            acc7 = acc7 + acc8;
            d0123[i + j] = reduce32to16(d0123[i + j] + (int32_t)acc5 * acc7);
        }
    }


    for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
        d0123[i] = d0123[i] - result_d01[i + 0 * KARATSUBA_N / 4] - result_d01[i + 2 * KARATSUBA_N / 4]; 
        d01[i] = d01[i] - result_final[i + 0 * KARATSUBA_N / 4] - result_final[i + 2 * KARATSUBA_N / 4]; 
        d23[i] = d23[i] - result_final[i + 4 * KARATSUBA_N / 4] - result_final[i + 6 * KARATSUBA_N / 4]; 
    }

    for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
        result_d01[i + 1 * KARATSUBA_N / 4] = barrett_reduceq(result_d01[i + 1 * KARATSUBA_N / 4] + d0123[i]); 
        result_final[i + 1 * KARATSUBA_N / 4] = barrett_reduceq(result_final[i + 1 * KARATSUBA_N / 4] + d01[i]); 
        result_final[i + 5 * KARATSUBA_N / 4] = barrett_reduceq(result_final[i + 5 * KARATSUBA_N / 4] + d23[i]); 
    }

    for (i = 0; i < KARATSUBA_N - 1; i++) {
        result_d01[i] = result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N];
    }

    for (i = 0; i < KARATSUBA_N - 1; i++) {
        result_final[i + 1 * KARATSUBA_N / 2] = barrett_reduceq(result_final[i + 1 * KARATSUBA_N / 2] + result_d01[i]);
    }

}


static void toom_cook_4way_lazy (const int16_t *a1, const int16_t *b1, int16_t *result) {
    int16_t inv2 = 1962, inv24 = 2125, inv18 = 218, inv60 = 850;

    int16_t aw1[N_SB], aw2[N_SB], aw3[N_SB], aw4[N_SB], aw5[N_SB], aw6[N_SB], aw7[N_SB];
    int16_t bw1[N_SB], bw2[N_SB], bw3[N_SB], bw4[N_SB], bw5[N_SB], bw6[N_SB], bw7[N_SB];
    int16_t w1[N_SB_RES] = {0}, w2[N_SB_RES] = {0}, w3[N_SB_RES] = {0}, w4[N_SB_RES] = {0}, w5[N_SB_RES] = {0}, w6[N_SB_RES] = {0}, w7[N_SB_RES] = {0};
    int16_t r0, r1, r2, r3, r4, r5, r6, r7;
    int16_t *A0, *A1, *A2, *A3, *B0, *B1, *B2, *B3;
    A0 = (int16_t *)a1;
    A1 = (int16_t *)&a1[N_SB];
    A2 = (int16_t *)&a1[2 * N_SB];
    A3 = (int16_t *)&a1[3 * N_SB];
    B0 = (int16_t *)b1;
    B1 = (int16_t *)&b1[N_SB];
    B2 = (int16_t *)&b1[2 * N_SB];
    B3 = (int16_t *)&b1[3 * N_SB];

    int32_t C[2*N_MUL]={0};

    int i, j;

    // EVALUATION
    for (j = 0; j < N_SB; ++j) {
        r0 = A0[j];
        r1 = A1[j];
        r2 = A2[j];
        r3 = A3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = barrett_reduceq(r4 + r5);
        r7 = barrett_reduceq(r4 - r5);
        aw3[j] = r6;
        aw4[j] = r7;
        r4 = reduce32to16((((int32_t)r0 << 2) + r2) << 1);
        r5 = reduce32to16(((int32_t)r1 << 2) + r3);
        r6 = barrett_reduceq((r4 + r5));
        r7 = barrett_reduceq((r4 - r5));
        aw5[j] = r6;
        aw6[j] = r7;
        r4 = reduce32to16(((int32_t)r3 << 3) + ((int32_t)r2 << 2) + ((int32_t)r1 << 1) + r0);
        aw2[j] = r4;
        aw7[j] = r0;
        aw1[j] = r3;
    }
    for (j = 0; j < N_SB; ++j) {
        r0 = B0[j];
        r1 = B1[j];
        r2 = B2[j];
        r3 = B3[j];
        r4 = r0 + r2;
        r5 = r1 + r3;
        r6 = barrett_reduceq(r4 + r5);
        r7 = barrett_reduceq(r4 - r5);
        bw3[j] = r6;
        bw4[j] = r7;
        r4 = reduce32to16((((int32_t)r0 << 2) + r2) << 1);
        r5 = reduce32to16(((int32_t)r1 << 2) + r3);
        r6 = barrett_reduceq(r4 + r5);
        r7 = barrett_reduceq(r4 - r5);
        bw5[j] = r6;
        bw6[j] = r7;
        r4 = reduce32to16(((int32_t)r3 << 3) + ((int32_t)r2 << 2) + ((int32_t)r1 << 1) + r0);
        bw2[j] = r4;
        bw7[j] = r0;
        bw1[j] = r3;
    }

    // MULTIPLICATION

    karatsuba_simple_lazy(aw1, bw1, w1);
    karatsuba_simple_lazy(aw2, bw2, w2);
    karatsuba_simple_lazy(aw3, bw3, w3);
    karatsuba_simple_lazy(aw4, bw4, w4);
    karatsuba_simple_lazy(aw5, bw5, w5);
    karatsuba_simple_lazy(aw6, bw6, w6);
    karatsuba_simple_lazy(aw7, bw7, w7);

    // INTERPOLATION
    for (i = 0; i < N_SB_RES; ++i) {
        r0 = w1[i];
        r1 = w2[i];
        r2 = w3[i];
        r3 = w4[i];
        r4 = w5[i];
        r5 = w6[i];
        r6 = w7[i];

        r1 = r1 + r4; 
        r5 = r5 - r4; 
        r3 = reduce32to16(((int32_t)r3 - r2) * inv2); 
        r4 = r4 - r0; 
        r4 = reduce32to16(r4 - ((int32_t)r6 << 6)); 
        r4 = reduce32to16(((int32_t)r4 << 1) + r5);
        r2 = barrett_reduceq(r2 + r3);
        r1 = reduce32to16(r1 - ((int32_t)r2 << 6) - r2);
        r2 = r2 - r6;
        r2 = r2 - r0;
        r1 = reduce32to16(r1 + 45 * (int32_t)r2);
        r4 = reduce32to16((r4 - ((int32_t)r2 << 3)) * inv24);
        r5 = r5 + r1;
        r1 = reduce32to16((r1 + ((int32_t)r3 << 4)) * inv18);
        r3 = -(r3 + r1);
        r5 = reduce32to16((30 * (int32_t)r1 - r5) * inv60);
        r2 = r2 - r4;
        r1 = r1 - r5;
        C[i]     = r6 + C[i];
        C[i + 68]  = r5 + C[i + 68];
        C[i + 136] = r4 + C[i + 136];
        C[i + 204] = r3 + C[i + 204];
        C[i + 272] = r2 + C[i + 272];
        C[i + 340] = r1 + C[i + 340];
        C[i + 408] = r0 + C[i + 408];
    }
    
    for (i = 0; i < 2*N_MUL; ++i){
        result[i] = reduce32to16(C[i]);
    }

}

/* res += a*b */
void poly_mul_acc(int16_t res[KYBER_N], const int16_t a[KYBER_N], const int16_t b[KYBER_N])
{
	int16_t c[2 * N_MUL] = {0};
    int16_t a_star[N_MUL] = {0};
    int16_t b_star[N_MUL] = {0};
    int32_t tmp[257];
	int i;

    for(i = 0; i < KYBER_N; i++){
        a_star[i] = a[i];
        b_star[i] = b[i];
    }

	toom_cook_4way_lazy(a_star, b_star, c);

    tmp[0] = c[0] + c[257];
    for(i = 1; i < 256; i++)
        tmp[i] = c[i + 256] + c[i + 257] + c[i];
    tmp[256] = c[256] + c[512];

    for(i = 0; i < 257; ++i)
        res[i] = reduce32to16(tmp[i]);
        
}
