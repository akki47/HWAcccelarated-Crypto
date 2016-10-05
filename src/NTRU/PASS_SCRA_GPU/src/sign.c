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

#define MLEN 256

static uint16 randpool[RAND_LEN];
static int randpos;

#define NO_MSGS 8192

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
		const unsigned char *message, const int msglen, int k)
{
	int count;
	//b_sparse_poly *c = malloc(k*sizeof(b_sparse_poly));
	b_sparse_poly c[512];

//	for(int i=0;i<512;i++)
//	{
//		c[i].ind = 0;
//		c[i].val = 0;
//	}

	int64 *y = malloc(PASS_N * sizeof(int64)*k);
	int64 *Fy = malloc(PASS_N * sizeof(int64)*k);
	unsigned char msg_digest[HASH_BYTES];

	//printf("\nreached here\n");
	int i,j;
	//  for(i=0;i<(16);i++)
	//  {
	//	  for(j=0;j<PASS_N;j++)
	//	  {
	//		  //y[i][j]=0; printf("\nreached here\n");
	//	  }
	//  }
	//printf("\nreached here\n");

	crypto_hash_sha512(msg_digest, message, msglen);

	//printf("Started GPU allocation");
	count = 0;

	int64 *d_y = malloc(PASS_N * sizeof(int64)*k);
	int64 *d_Fy = malloc(PASS_N * sizeof(int64)*k);

	cudaMalloc(&d_y, (PASS_N * sizeof(int64))*k);
	cudaMalloc(&d_Fy, (PASS_N * sizeof(int64))*k);

	cudaMemcpy(d_y,y,(PASS_N * sizeof(int64))*k,cudaMemcpyHostToDevice);
	cudaMemcpy(d_Fy,Fy,(PASS_N * sizeof(int64))*k,cudaMemcpyHostToDevice);

	//do {

	for( i=0;i<k;i++)
	{
		CLEAR((Fy+(i*PASS_N)));
		mknoise(y+(i*PASS_N));
	}


	ntt_gpu(d_Fy, d_y,k);

	cudaMemcpy(y,d_y,(PASS_N * sizeof(int64)*k),cudaMemcpyDeviceToHost);

	//gpu memory allocation
	//int64 d_y[PASS_N];
	int64 d_key[PASS_N];
	b_sparse_poly d_c;
	//b_sparse_poly *cp= malloc(k*sizeof(b_sparse_poly));


	//cudaMalloc(&d_y, (PASS_N * sizeof(int64))*k);
	cudaMalloc(&d_key, (PASS_N * sizeof(int64)));
	cudaMalloc(&d_c, (sizeof(b_sparse_poly))*k);

	for( i=0;i<k;i++)
	{
		hash(h, (Fy+(i*PASS_N)), msg_digest);
		CLEAR(c[0].val);
		formatc(&c[0], h);
		//memcpy((cp+(i*sizeof(b_sparse_poly))),&c,sizeof(b_sparse_poly));
	}

	//printf("\ncheckpoint for k = %d\n",k);
	//cudaMemcpy(y,d_y,(PASS_N * sizeof(int64))*k,cudaMemcpyDeviceToHost);
	cudaMemcpy(&d_c,&c, sizeof(b_sparse_poly)*k,cudaMemcpyHostToDevice);
	cudaMemcpy(d_key,key,(PASS_N * sizeof(int64)),cudaMemcpyHostToDevice);
	/* z = y += f*c */
	bsparseconv_gpu(d_y, d_key, &d_c,k);

	cudaMemcpy(y,d_y,(PASS_N * sizeof(int64)*k),cudaMemcpyDeviceToHost);
	/* No modular reduction required. */

	count++;
	int counter=0;
	for(i=0;i<k;i++)
	{
		if(reject(y))
			counter++; //counting rejected signatures
	}
	//printf("\n%d signatures were rejected\n",counter);
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
	//printf("\nreached here\n");
	for(i=0;i<k;i++)
	{
		//printf("\nreached here too %d\n",i);
		memcpy(z, (y+(i*PASS_N)), PASS_N*sizeof(int64));
	}


	return count;
}

