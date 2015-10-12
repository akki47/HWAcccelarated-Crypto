#ifndef __SHA_CONTEXT__
#define __SHA_CONTEXT__

#include "cuda_mem_pool.hh"
#include "device_context.hh"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

using namespace std;

typedef struct sha1_param
{
	uint8_t         *memory_start;
	unsigned long   pkt_offset_pos;
	unsigned long   in_pos;
	unsigned long   key_pos;
	unsigned long   length_pos;
	unsigned        total_size;
	unsigned        num_flows;
	uint8_t         *out;
} sha1_param_t;

typedef enum {RSA_PRIV_DEC, AES_ENC, AES_DEC, SHA_1} opcode_t;

typedef struct operation
{
	operation() {
		memset(this, 0, sizeof(*this));
	};

	~operation() {
		destroy();
	};

	void destroy() {
		if (in)
			free(in);
		in = NULL;

		if (out)
			free(out);
		out = NULL;

		if (key)
			free(key);
		key = NULL;

		if (iv)
			free(iv);
		iv = NULL;
	};

	opcode_t     op;
	uint8_t      *in;
	uint32_t     in_len;
	uint8_t      *out;
	uint32_t     out_len;
	uint8_t      *key; //RSA key is preloaded and this field should be null
	uint32_t     key_len;
	uint8_t      *iv;  //Used for AES only
	uint32_t     iv_len;
} operation_t;

typedef vector<operation_t> operation_batch_t;

typedef enum {CPU, MP, RNS} RSA_MODE;

/**
 * class sha_context
 *
 * Interface for HMAC-SHA1 in GPU.
 */
class sha_context {
public:
	/**
	 * Constructor.
	 *
	 * @param dev_ctx Device context pointer.
	 * Device context must be initialized before calling this function.
	 */
	sha_context(device_context *dev_ctx);

	~sha_context();

	/**
	 * It executes hmac_sha1 in GPU.
	 * If stream is enabled it will run in non-blocking mode,
	 * if not, it will run in blocking mode and the result
	 * will be written back to out at the end of function call.
	 * This function takes one or more data  and
	 * returns HMAC-SHA1 value for all of them.
	 *
	 * @param memory_start Starting point of input data.
	 * All input data should be be packed in to single continous region
	 * before making call to this function.
	 * @param in_pos Offset of plain texts.
	 * @param keys_pos Offset of region that stores HHAC keys.
	 * @param pkt_offset_pos Offset of region that stores
	 * position of each plain text.
	 * @param lengths_pos Offset of region that stores length of
	 * each plain text.
	 * @param data_size Total amount of input data.
	 * @param out Buffer to store output.
	 * @param num_flows Number of plain texts to be hashed.
	 * @param stream_id Stream index.
	 */
        void hmac_sha1(const void           *memory_start,
		       const unsigned long  in_pos,
		       const unsigned long  keys_pos,
		       const unsigned long  pkt_offset_pos,
		       const unsigned long  lengths_pos,
		       const unsigned long  data_size,
		       unsigned char        *out,
		       const unsigned long  num_flows,
		       unsigned int         stream_id);

     /**
   	 * @param memory_start Starting point of input data.
   	 * All input data should be be packed in to single continous region
   	 * before making call to this function.
   	 * @param in_pos Offset of plain texts.
   	 * @param keys_pos Offset of region that stores HHAC keys.
   	 * @param pkt_offset_pos Offset of region that stores
   	 * position of each plain text.
   	 * @param lengths_pos Offset of region that stores length of
   	 * each plain text.
   	 * @param data_size Total amount of input data.
   	 * @param out Buffer to store output.
   	 * @param num_flows Number of plain texts to be hashed.
   	 * @param stream_id Stream index.
   	 */
           void sha1(const void           *memory_start,
   		       const unsigned long  in_pos,
   		       const unsigned long  keys_pos,
   		       const unsigned long  pkt_offset_pos,
   		       const unsigned long  lengths_pos,
   		       const unsigned long  data_size,
   		       unsigned char        *out,
   		       const unsigned long  num_flows,
   		       unsigned int         stream_id);

	/**
	 * Synchronize/query the execution on the stream.
	 * This function can be used to check whether the current execution
	 * on the stream is finished or also be used to wait until
	 * the execution to be finished.
	 *
	 * @param stream_id Stream index.
	 * @param block Wait for the execution to finish or not. true by default.
	 * @param copy_result If false, it will not copy result back to CPU.
	 *
	 * @return true if the current operation on the stream is finished
	 * otherwise false.
	 */
	bool sync(const unsigned int  stream_id,
		  const bool          block = true,
		  const bool          copy_result = true);

	void calculate_sha1(const unsigned char **m, const unsigned int *flow_len,
			unsigned char **digest,unsigned int num_flows);

	void sha1_prepare(operation_batch_t *ops,
			       sha1_param_t *param,
			       pinned_mem_pool   *pool);

	void sha1_post(operation_batch_t *ops,
			    sha1_param_t   *param);

	void gen_sha1_data2(operation_batch_t *ops,
				const unsigned char **m,
				unsigned   int       num_flows,
				const unsigned  int        *flow_len);

private:
	struct {
		uint8_t        *out;
		uint8_t        *out_d;
		unsigned long  out_len;
	} streams[MAX_STREAM + 1];

	device_context *dev_ctx_;

};
#endif/*__SHA_CONTEXT__*/
