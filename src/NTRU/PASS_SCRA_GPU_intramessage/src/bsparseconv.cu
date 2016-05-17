#include "constants.h"
#include "pass_types.h"


extern "C" {
#include "bsparseconv.h"
}



__global__ void bsparseconv_kernel(int64 *c, const int64 *a, const b_sparse_poly *b)
{
  int64 i = 0;
  int64 k = 0;

  int thread = threadIdx.x + blockDim.x*blockIdx.x;

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


extern "C" void bsparseconv_gpu(int64 *c, const int64 *a, const b_sparse_poly *b)
{
	int msg_count=1;
	unsigned int num_blocks = msg_count ;
	unsigned int num_threads = PASS_N;

	    /* z = y += f*c */
	bsparseconv_kernel<<<num_blocks,num_threads>>>(c, a, b);
	    /* No modular reduction required. */
}

