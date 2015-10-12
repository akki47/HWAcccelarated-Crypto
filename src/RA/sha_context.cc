#include "sha_context.hh"
#include "sha1.hh"

#include <assert.h>
#include <cuda_runtime.h>
#include <helper_cuda.h>
#include <vector>

using namespace std;

#define SHA1_HASH_SIZE 20

void set_random1(unsigned char *buf, int len)
{
	for (int i = 0; i < len; i++)
		buf[i] = rand() % 256;
}

sha_context::sha_context(device_context *dev_ctx)
{
	for (unsigned i = 0; i <MAX_STREAM; i++) {
		streams[i].out = 0;
		streams[i].out_d = 0;
		streams[i].out_len = 0;
	}
	dev_ctx_ = dev_ctx;
}

sha_context::~sha_context()
{
}


void sha_context::hmac_sha1(const void           *memory_start,
			    const unsigned long  in_pos,
			    const unsigned long  keys_pos,
			    const unsigned long  offsets_pos,
			    const unsigned long  lengths_pos,
			    const unsigned long  data_size,
			    unsigned char        *out,
			    const unsigned long  num_flows,
			    const unsigned int   stream_id)
{
	assert(dev_ctx_->get_state(stream_id) == READY);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);
	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);
	void *memory_d = pool->alloc(data_size);;

	//copy input data
	cudaMemcpyAsync(memory_d,
			memory_start,
			data_size,
			cudaMemcpyHostToDevice,
			dev_ctx_->get_stream(stream_id));

	//variables need for kernel launch
	int threads_per_blk = SHA1_THREADS_PER_BLK;
	int num_blks = (num_flows+threads_per_blk-1)/threads_per_blk;

	//allocate buffer for output
	uint32_t *out_d = (uint32_t *)pool->alloc(20 * num_flows);

	//initialize input memory offset in device memory
	char     *in_d         = (char *)memory_d + in_pos;
	char     *keys_d       = (char *)memory_d + keys_pos;
	uint32_t *pkt_offset_d = (uint32_t *)((uint8_t *)memory_d + offsets_pos);
	uint16_t *lengths_d    = (uint16_t *)((uint8_t *)memory_d + lengths_pos);

	//clear checkbits before kernel execution
	dev_ctx_->clear_checkbits(stream_id, num_blks);

	if (dev_ctx_->use_stream() && stream_id > 0) {	//with stream
		hmac_sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      threads_per_blk,
			      dev_ctx_->get_stream(stream_id));
	} else  if (!dev_ctx_->use_stream() && stream_id == 0) {//w/o stream
		hmac_sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      SHA1_THREADS_PER_BLK);
	} else {
		assert(0);
	}

	assert(cudaGetLastError() == cudaSuccess);

	streams[stream_id].out_d   = (uint8_t*)out_d;
	streams[stream_id].out     = out;
	streams[stream_id].out_len = 20 * num_flows;

	//if stream is not used then sync (assuming blocking mode)
	if (dev_ctx_->use_stream() && stream_id == 0) {
		sync(stream_id);
	}
}

void sha_context::sha1(const void           *memory_start,
			    const unsigned long  in_pos,
			    const unsigned long  keys_pos,
			    const unsigned long  offsets_pos,
			    const unsigned long  lengths_pos,
			    const unsigned long  data_size,
			    unsigned char        *out,
			    const unsigned long  num_flows,
			    const unsigned int   stream_id)
{
	assert(dev_ctx_->get_state(stream_id) == READY);
	dev_ctx_->set_state(stream_id, WAIT_KERNEL);
	cuda_mem_pool *pool = dev_ctx_->get_cuda_mem_pool(stream_id);
	void *memory_d = pool->alloc(data_size);;

	//copy input data
	cudaMemcpyAsync(memory_d,
			memory_start,
			data_size,
			cudaMemcpyHostToDevice,
			dev_ctx_->get_stream(stream_id));

	//variables need for kernel launch
	int threads_per_blk = SHA1_THREADS_PER_BLK;
	int num_blks = (num_flows+threads_per_blk-1)/threads_per_blk;

	//allocate buffer for output
	uint32_t *out_d = (uint32_t *)pool->alloc(20 * num_flows);

	//initialize input memory offset in device memory
	char     *in_d         = (char *)memory_d + in_pos;
	char     *keys_d       = (char *)memory_d + keys_pos;
	uint32_t *pkt_offset_d = (uint32_t *)((uint8_t *)memory_d + offsets_pos);
	uint16_t *lengths_d    = (uint16_t *)((uint8_t *)memory_d + lengths_pos);

	//clear checkbits before kernel execution
	dev_ctx_->clear_checkbits(stream_id, num_blks);

	if (dev_ctx_->use_stream() && stream_id > 0) {	//with stream
		sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      threads_per_blk,
			      dev_ctx_->get_stream(stream_id));
	} else  if (!dev_ctx_->use_stream() && stream_id == 0) {//w/o stream
		sha1_gpu(in_d,
			      keys_d,
			      pkt_offset_d,
			      lengths_d,
			      out_d,
			      num_flows,
			      dev_ctx_->get_dev_checkbits(stream_id),
			      SHA1_THREADS_PER_BLK);
	} else {
		assert(0);
	}

	assert(cudaGetLastError() == cudaSuccess);

	streams[stream_id].out_d   = (uint8_t*)out_d;
	streams[stream_id].out     = out;
	streams[stream_id].out_len = 20 * num_flows;

	//if stream is not used then sync (assuming blocking mode)
	if (dev_ctx_->use_stream() && stream_id == 0) {
		sync(stream_id);
	}
}

bool sha_context::sync(const unsigned int  stream_id,
		       const bool          block,
		       const bool          copy_result)
{
        if (block) {
		dev_ctx_->sync(stream_id, true);
		if (copy_result && dev_ctx_->get_state(stream_id) == WAIT_KERNEL) {
			checkCudaErrors(cudaMemcpyAsync(streams[stream_id].out,
						      streams[stream_id].out_d,
						      streams[stream_id].out_len,
						      cudaMemcpyDeviceToHost,
						      dev_ctx_->get_stream(stream_id)));
			dev_ctx_->set_state(stream_id, WAIT_COPY);
			dev_ctx_->sync(stream_id, true);
		}
		if (dev_ctx_->get_state(stream_id) == WAIT_COPY) {
			dev_ctx_->sync(stream_id, true);
			dev_ctx_->set_state(stream_id, READY);
		}
		return true;
	} else {
		if (!dev_ctx_->sync(stream_id, false))
			return false;

		if (dev_ctx_->get_state(stream_id) == WAIT_KERNEL) {
			//if no need for data copy
			if (!copy_result) {
				dev_ctx_->set_state(stream_id, READY);
				return true;
			}

			checkCudaErrors(cudaMemcpyAsync(streams[stream_id].out,
						      streams[stream_id].out_d,
						      streams[stream_id].out_len,
						      cudaMemcpyDeviceToHost,
						      dev_ctx_->get_stream(stream_id)));
			dev_ctx_->set_state(stream_id, WAIT_COPY);

		} else if (dev_ctx_->get_state(stream_id) == WAIT_COPY) {
			dev_ctx_->set_state(stream_id, READY);
			return true;

		} else if (dev_ctx_->get_state(stream_id) == READY) {
			return true;

		} else {
			assert(0);
		}
	}
        return false;
}

void sha_context::gen_sha1_data2(operation_batch_t *ops,
			const unsigned char **m,
			unsigned   int       num_flows,
			const unsigned  int        *flow_len)
{
	//assert(flow_len  > 0 && flow_len  <= MAX_FLOW_LEN);
	//assert(num_flows > 0 && num_flows <= 4096);
	assert(ops != NULL);

	//prepare buffer for data generation
	ops->resize(num_flows);

	int count=0;
	//generate random data
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		(*i).destroy();

		//input data
		(*i).in_len  = flow_len[count];
		(*i).in      = (uint8_t*)malloc(flow_len[count]);
		assert((*i).in != NULL);
		//set_random1((*i).in, flow_len[count]);
		memcpy((*i).in,m[count],flow_len[count]);

		//output data
		(*i).out_len = SHA1_HASH_SIZE;
		(*i).out     = (uint8_t*)malloc(SHA1_HASH_SIZE);
		assert((*i).out != NULL);
		//set_random1((*i).out, SHA1_HASH_SIZE);

		//key
		(*i).key_len = MAX_KEY_SIZE;
		(*i).key     = (uint8_t*)malloc(MAX_KEY_SIZE);
		assert((*i).key != NULL);
		//set_random1((*i).key, MAX_KEY_SIZE);

		(*i).op = SHA_1;
		count++;

	}

}


void sha_context::sha1_post(operation_batch_t *ops,
		    sha1_param_t   *param)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);

	unsigned sum_outsize = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		memcpy((*i).out,   param->out + sum_outsize,   (*i).out_len);
		sum_outsize += (*i).out_len;
	}
}


void sha_context::sha1_prepare(operation_batch_t *ops,
		       sha1_param_t *param,
		       pinned_mem_pool   *pool)
{
	assert(ops != NULL);
	assert(ops->size() > 0);
	assert(param != NULL);
	assert(pool != NULL);

	uint32_t *pkt_offset;
	uint8_t  *in;
	uint16_t *lengths;
	uint8_t  *keys;
	uint8_t  *out;

	unsigned tot_in_size = 0; /* total size of input text */

	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		assert((*i).in_len > 0);
		tot_in_size += (*i).in_len;
	}

	unsigned long num_flows = ops->size();

	//allocate memory
	pkt_offset = (uint32_t *)pool->alloc(sizeof(uint32_t) * (num_flows));
	keys       = (uint8_t  *)pool->alloc(num_flows * MAX_KEY_SIZE);
	in         = (uint8_t  *)pool->alloc(tot_in_size);
	lengths     = (uint16_t *)pool->alloc(sizeof(uint16_t) * num_flows);
	out        = (uint8_t  *)pool->alloc(SHA1_HASH_SIZE * num_flows);

	assert(pkt_offset != NULL);
	assert(keys       != NULL);
	assert(in         != NULL);
	assert(lengths    != NULL);
	assert(out        != NULL);

	//copy data into pinned memory and set metadata
	unsigned cnt = 0;
	unsigned sum_input = 0;
	for (operation_batch_t::iterator i = ops->begin();
	     i != ops->end(); i++) {
		pkt_offset[cnt] = sum_input;
		lengths[cnt]    = (*i).in_len;

		memcpy(keys + cnt * MAX_KEY_SIZE, (*i).key,  MAX_KEY_SIZE);
		memcpy(in + sum_input,  (*i).in,   (*i).in_len);

		cnt++;
		sum_input += (*i).in_len;
	}

	//set param for sha_context api
	param->memory_start   = (uint8_t*)pkt_offset;
	param->pkt_offset_pos = (unsigned long)((uint8_t *)pkt_offset -
						param->memory_start);
	param->in_pos         = (unsigned long)(in      - param->memory_start);
	param->key_pos        = (unsigned long)(keys    - param->memory_start);
	param->length_pos     = (unsigned long)((uint8_t *)lengths
						- param->memory_start);
	param->total_size     = (unsigned long)(out     - param->memory_start);

	param->out            = out;
	param->num_flows      = num_flows;
}

void sha_context::calculate_sha1(const unsigned char **m, const unsigned int *flow_len,unsigned char **digest,unsigned int num_flows)
{
	pinned_mem_pool *pool;
	pool = new pinned_mem_pool();
	pool->init(num_flows *  512 * 2.2);

	operation_batch_t ops;
	sha1_param_t param;

//	unsigned int flowLengths[num_flows];
//	for(unsigned int i=0;i<num_flows;i++)
//	{
//		flowLengths[i] = 512; //(rand() % 512) + 1;
//	}

	gen_sha1_data2(&ops, m, num_flows, flow_len);
	sha1_prepare(&ops, &param, pool);

	sha1((void*)param.memory_start,
			  param.in_pos,
			  param.key_pos,
			  param.pkt_offset_pos,
			  param.length_pos,
			  param.total_size,
			  param.out,
			  param.num_flows,
			  0);

	sync(0);
	sha1_post(&ops, &param);

	delete pool;

	int count=0;
	for (operation_batch_t::iterator i = ops.begin();
		  i != ops.end(); i++) {
		memcpy(digest[count] ,(*i).out, SHA1_HASH_SIZE);
		count++;
	}
}




