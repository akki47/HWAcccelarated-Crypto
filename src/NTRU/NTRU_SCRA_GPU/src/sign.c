/*
 * CPASSREF/sign.c
 *
 *  Copyright 2013 John M. Schanck
 *
 *  This file is part of CPASSREF.
 *
 *  CPASSREF is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  CPASSREF is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with CPASSREF.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "formatc.h"
#include "bsparseconv.h"
#include "ntt.h"
#include "hash.h"
#include "fastrandombytes.h"
#include "pass.h"

#include </usr/local/cuda-6.5/include/cuda.h>
#include </usr/local/cuda-6.5/include/cuda_runtime.h>


#define CLEAR(f) memset((f), 0, PASS_N*sizeof(int64))

#define RAND_LEN (4096)

static uint16 randpool[RAND_LEN];
static int randpos;

int
circ_conv(int64 *c, const int64 *a, const int64 *b)
{
	 int i,j,k;
	 c[0]=0;
	 int64 d[PASS_N];
	 int64 x2[PASS_N];

	 d[0]=b[0];

	for(j=1;j<PASS_N;j++)            /*folding h(n) to h(-n)*/
		d[j]=b[PASS_N -j];

	 for(i=0;i<PASS_N;i++)
		 c[0] += a[i]*d[i];

	for(k=1;k<PASS_N;k++)
	{
				c[k]=0;
				/*circular shift*/

				for(j=1;j<PASS_N;j++)
					x2[j]=d[j-1];
				x2[0]=d[PASS_N-1];
				for(i=0;i<PASS_N;i++)
				{
							d[i]=x2[i];
							c[k]+=a[i]*x2[i];
				}
				c[k] = c[k]/PASS_b; //this should be q, check again (might be source of error)
	}
	return 0;
}

int
init_fast_prng()
{
  fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
  randpos = 0;

  return 0;
}

int
mknoise(int64 *y)
{
  int i = 0;
  int x;
  while(i < PASS_N) {
    if(randpos == RAND_LEN) {
      fastrandombytes((unsigned char*)randpool, RAND_LEN*sizeof(uint16));
      randpos = 0;
    }
    x = randpool[randpos++];

    if(x >= UNSAFE_RAND_k) continue;

    x &= (2*PASS_k + 1);

    y[i] = x - PASS_k;
    i++;
  }

  return 0;
}

int
reject(const int64 *z)
{
  int i;

  for(i=0; i<PASS_N; i++) {
    if(abs(z[i]) > (PASS_k - PASS_b))
      return 1;
  }

  return 0;
}

int
sign(unsigned char *h, int64 *z, const int64 *key,
    const unsigned char *message, const int msglen, const int64 *pubkey, int k)
{
  int count;
  b_sparse_poly c;
  int64 y[PASS_N];
  int64 x[PASS_N];
  int64 Fy[PASS_N];

  //secret polynomial g
  int64 g[PASS_N];
  unsigned char msg_digest[HASH_BYTES];

  crypto_hash_sha512(msg_digest, message, msglen);
  int i;
  count = 0;
  //do {
    CLEAR(Fy);

   // mknoise(y);
   // ntt(Fy, y);
    
    mknoise(y);
   // ntt_gpu(Fy,y,k);	
    		

    for( i=0;i<k;i++)
      {

//	mknoise(y);
    	ntt(Fy, y);
        hash(h, Fy, msg_digest);
        CLEAR(c.val);
        formatc(&c, h);
        circ_conv(g,key,pubkey);
      }

    //Original NTRUSign protocol

    //generating polynomial g = f*h (move this to a seperate generate keys method because this can cause
    //problems in performance comp)


    int64 d_x[PASS_N];
    int64 d_y[PASS_N];
	int64 d_g[PASS_N];
	int64 d_key[PASS_N];
	b_sparse_poly d_c;

	cudaMalloc(&d_x, (PASS_N * sizeof(int64))*k);
	cudaMalloc(&d_g, (PASS_N * sizeof(int64))*k);
	cudaMalloc(&d_c, (sizeof(b_sparse_poly))*k);
	cudaMalloc(&d_y, (PASS_N * sizeof(int64))*k);
	cudaMalloc(&d_key, (PASS_N * sizeof(int64)));

	cudaMemcpy(x,d_x,(PASS_N * sizeof(int64)*k),cudaMemcpyDeviceToHost);
	cudaMemcpy(&c,&d_c, sizeof(b_sparse_poly)*k,cudaMemcpyDeviceToHost);
	cudaMemcpy(g,d_g,(PASS_N * sizeof(int64))*k,cudaMemcpyDeviceToHost);
	cudaMemcpy(y,d_y,(PASS_N * sizeof(int64))*k,cudaMemcpyDeviceToHost);
	cudaMemcpy(key,d_key,(PASS_N * sizeof(int64)),cudaMemcpyDeviceToHost);
    //bsparseconv(x,g,&c); //generating x = (-1/q)m*g
    bsparseconv_gpu(d_x, d_g, &d_c,k);
    cudaMemcpy(x,d_x,(PASS_N * sizeof(int64)*k),cudaMemcpyDeviceToHost);


    /* z = y += f*c */
    bsparseconv_gpu(d_y, d_key, &d_c,k);	//generating y = (1/q)m*f
    /* No modular reduction required. */

    cudaMemcpy(y,d_y,(PASS_N * sizeof(int64)*k),cudaMemcpyDeviceToHost);
//    cudaFree(d_y);
//    cudaFree(d_x);
//    cudaFree(d_key);
//    cudaFree(d_g);
//    cudaFree(&d_c);

    i=0;
    for(i=0;i<PASS_N;i++)
    {
    	y[i] = y[i]-x[i];
    }


    count++;
  //} while (reject(y));

#if DEBUG
  int i;
  printf("\n\ny: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) y[i]));
  printf("\n");

  printf("\n\nFy: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) Fy[i]));
  printf("\n");

  printf("\n\nc: ");
  for(i=0; i<PASS_b; i++)
    printf("(%lld, %lld) ", (long long int) c.ind[i],
        (long long int) c.val[c.ind[i]]);
  printf("\n");
#endif

  for(i=0;i<k;i++)
  {
  memcpy(z, y, PASS_N*sizeof(int64));
  }
  return count;
}

