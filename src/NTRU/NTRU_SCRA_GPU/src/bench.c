/*
 * CPASSREF/bench.c
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
#include <time.h>
#include <openssl/sha.h>

#include "constants.h"
#include "pass_types.h"
#include "hash.h"
#include "ntt.h"
#include "pass.h"

#ifndef VERIFY
#define VERIFY 1
#endif

#ifndef TRIALS
#define TRIALS 10000
#endif

#define MLEN 256
#define NO_MSGS 8192


int
main(int argc, char **argv)
{
  int i;
  int count;
  float scra,ver,on;

  int64 key[PASS_N];
  int64 *z;
  unsigned char in[MLEN+1] = {0};
  unsigned char h[NO_MSGS][HASH_BYTES];

  memset(in, '0', MLEN);
  z = malloc(PASS_N * sizeof(int64));

  init_fast_prng();

  if(ntt_setup() == -1) {
    fprintf(stderr,
        "ERROR: Could not initialize FFTW. Bad wisdom?\n");
    exit(EXIT_FAILURE);
  }

  printf("Parameters:\n\t N: %d, p: %d, g: %d, k: %d, b: %d, t: %d\n\n",
      PASS_N, PASS_p, PASS_g, PASS_k, PASS_b, PASS_t);

  printf("Generating %d signatures %s\n", TRIALS,
          VERIFY ? "and verifying" : "and not verifying");

  gen_key(key);

#if DEBUG
  printf("sha512(key): ");
  crypto_hash_sha512(h, (unsigned char*)key, sizeof(int64)*PASS_N);
  for(i=0; i<HASH_BYTES; i++) {
    printf("%.2x", h[i]);
  }
  printf("\n");
#endif

#if VERIFY
  int nbver = 0;

  int64 pubkey[PASS_N] = {0};
  gen_pubkey(pubkey, key);
#endif

  int k;
  printf("\n#msg \t without SCRA \t Offline Stage \t Online Stage \t Verify Stage \t With SCRA");

  for(k=32;k< NO_MSGS; k=k*2)
  {
  clock_t c0,c1,off0,off1,on0,on1,ver1,ver0;
  c0 = clock();

  for(i=0; i<k; i++) {
     in[(i&0xff)]++; /* Hash a different message each time */
     count += sign(h[i], z, key, in, MLEN, pubkey);
#if VERIFY
   nbver += (VALID == verify(h[i], z, pubkey, in, MLEN));
   #endif

    }
  c1 = clock();


  count = 0;
  // offline stage
  off0 = clock();
  for(i=0; i<k; i++) {
   in[(i&0xff)]++; /* Hash a different message each time */
   count += sign(h[i], z, key, in, MLEN, pubkey);


  }
  off1 = clock();
  //offline stage end
  printf("\n");

  SHA_CTX ctx;
  SHA1_Init(&ctx);

  on0 = clock();
  unsigned char hash[8192][SHA_DIGEST_LENGTH];
  int j;
  for(j=0;j<(k-16);j++)
  {

  for(i=0;i<16;i++) //online stage
  {
	  // Object to hold the current state of the hash


	  // Hash each piece of data as it comes in:
	  SHA1_Update(&ctx,h[i],HASH_BYTES);
  }


   SHA1_Final(hash[j], &ctx);
  }
   on1 = clock();
   //online stage end

  //verify stage
   ver0 = clock();
  SHA_CTX ctx2;
  SHA1_Init(&ctx2);

  for(i=0;i<k;i++)
  {
   #if VERIFY
   nbver += (VALID == verify(h[i], z, pubkey, in, MLEN));
   #endif
  }

  unsigned char hash_verify[8192][SHA_DIGEST_LENGTH];
  for(j=0;j<(k-16);j++)
  {
  for(i=0;i<16;i++)
  {
	  SHA1_Update(&ctx2,h[i],HASH_BYTES);
  }

   SHA1_Final(hash_verify[j], &ctx);
  }

  for(j=0;j<(k-16);j++)
  {
   if(memcmp(hash[j],hash_verify[j],SHA_DIGEST_LENGTH))
   {
	  // printf("\n aggregate verified \n");
   }
   else
   {
	   printf("\nerror occured\n");
	   exit(1);
   }
  }
   ver1 = clock();
  //verify stage end



  //printf("\nCPU\n");
  //printf("Total attempts: %d\n",  count);
#if VERIFY
  //printf("Valid signatures: %d/%d\n",  nbver, TRIALS);
#endif
  //printf("Attempts/sig: %f\n",  (((float)count)/TRIALS));
  //printf("Time/sig: %fs\n", (float) (c1 - c0)/(CLOCKS_PER_SEC));
  //printf("Time taken by Offline Stage: %fs\n", (float) (off1 - off0)/(CLOCKS_PER_SEC));
  //printf("Time taken by Online Stage:: %fs\n", (float) (on1 - on0)/(CLOCKS_PER_SEC));
  //printf("Time taken by Verify Stage:: %fs\n", (float) (ver1 - ver0)/(CLOCKS_PER_SEC));
   ver = (float) (ver1 - ver0)/(CLOCKS_PER_SEC);
   on = (float) (on1 - on0)/(CLOCKS_PER_SEC);
   printf("\n%4d\t\t%.5f\t\t%.5f\t\t%.5f\t\t%.5f\t\t%.5f\t\t\n",k,(float) (c1 - c0)/(CLOCKS_PER_SEC),(float) (off1 - off0)/(CLOCKS_PER_SEC),(float) (on1 - on0)/(CLOCKS_PER_SEC),(float) (ver1 - ver0)/(CLOCKS_PER_SEC), (on+ver));
  }
#if DEBUG
  printf("\n\nKey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) key[i]));

  #if VERIFY
  printf("\n\nPubkey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) pubkey[i]));
  printf("\n");
  #endif

  printf("\n\nz: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) z[i]));
  printf("\n");
#endif

  free(z);
  ntt_cleanup();
  return 0;
}

