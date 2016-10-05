#include "constants.h"
#include "pass_types.h"
#include "poly.h"
#include "ntt.h"



extern "C" {
#include "bsparseconv.h"
}

static const int64 perm2[NTT_LEN+1] = {
#include PASS_PERMUTATION
    , 1
  };


__global__ void bsparseconv_kernel(int64 *c, const int64 *a, const b_sparse_poly *b)
{
  int64 i = 0;
  int64 k = 0;

  int thread = threadIdx.x + blockDim.x*blockIdx.x;
  int msg_count = blockIdx.x;

  if(thread < PASS_N)
  {
  for (i = 0; i < PASS_b; i++) {
    k = b->ind[i];

    if(b->val[k] > 0) {

    		if(thread < k)
    		{

    				c[(thread)] += a[thread - k + PASS_N];

    		}
    		else //(thread >= k)
    		{

    				c[thread] += a[thread-k];

    		}

    }
  else
    { /* b->val[i] == -1 */
	  if(thread < k)
	  		{

	  				c[thread] -= a[thread - k + PASS_N];

	  		}
	  		else //(thread > k)
	  		{

	  				c[thread] -= a[thread-k];

	  		}
    }
  }
  }
  //return 0;
}


extern "C" void bsparseconv_gpu(int64 *c, const int64 *a, const b_sparse_poly *b, int k)
{
	int msg_count=1;
	unsigned int num_blocks = k ;
	unsigned int num_threads = PASS_N;

	    /* z = y += f*c */
	bsparseconv_kernel<<<num_blocks,num_threads>>>(c, a, b);
	    /* No modular reduction required. */
}

__global__ void ntt_kernel(int64 *Fw, const int64 *w, const int64 *perm)
{
	 int thread = threadIdx.x;
	 

		  int64 i;
  int64 j;

int64 nth_roots[NTT_LEN] = {
#include PASS_RADER_POLY
  };

  /* Rader DFT: Length N-1 convolution of w (permuted according to
   * PASS_PERMUTATION) and the vector [g, g^2, g^3, ... g^N-1].
   *
   * TODO: Certainly faster to always store coefficients in multiplicative
   * order and just perform permutation when publishing z or extracting
   * coefficients.
   */

  //printf("\nUsing incorrect ntt\n");

  for (i = 0; i < NTT_LEN; i++) {
    Fw[perm[i]] += w[0]; /* Each coefficient of Fw gets a w[0] contribution */

    if (w[perm[i]] == 0) continue;

    for (j = i; j < NTT_LEN; j++) {
      Fw[perm[NTT_LEN-j]] += (w[perm[i]] * nth_roots[j-i]);
    }

    for (j = 0; j < i; j++) {
      Fw[perm[NTT_LEN-j]] += (w[perm[i]] * nth_roots[NTT_LEN+j-i]);
    }
  }

  /* Fw[0] (evaluation of w at 1). */
  for (i = 0; i < PASS_N; i++) {
    Fw[0] += w[i];
  }

 // poly_cmod(Fw);

  for (i=0; i<PASS_N; i++) {
    if (Fw[i] >= 0) {
      Fw[i] %= PASS_p;
    } else {
      Fw[i] = PASS_p + (Fw[i] % PASS_p);
    }
    if (Fw[i] > ((PASS_p-1)/2))
      Fw[i] -= PASS_p;
  }


	
}

extern "C" int ntt_gpu(int64 *Fw, const int64 *w, int k)
{
   unsigned int num_blocks=1;	
   unsigned int num_threads = k ;

            /* z = y += f*c */
   ntt_kernel<<<num_blocks,num_threads>>>(Fw,w,perm);
   return 1;	
}

__global__ void circ_conv_kernel(int64 *c, const int64 *a, const int64 *b)
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

}

extern "C" int circ_conv_gpu(int64 *c, const int64 *a, const int64 *b,int k)
{
	unsigned int num_blocks=1;
    unsigned int num_threads = k ;

			/* z = y += f*c */
    circ_conv_kernel<<<num_blocks,num_threads>>>(c,a,b);
    return 1;

}



