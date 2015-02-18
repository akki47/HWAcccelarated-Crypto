#ifndef RSA_CONTEXT_RNS_HH
#define RSA_CONTEXT_RNS_HH

#include "rsa_context.hh"

#include "rsa_cuda.h"

class rsa_context_rns : public rsa_context
{
public:
	// generates a random key
	rsa_context_rns(int keylen);

	// currently supports PEM format only
	rsa_context_rns(const std::string &filename, const std::string &passwd);
	rsa_context_rns(const char *filename, const char *passwd);

	virtual ~rsa_context_rns();

	virtual void dump();

	// All encryption/decryption methods assume RSA_PKCS1_PADDING
	// out_len is an input+output variable
	virtual void priv_decrypt(unsigned char *out, int *out_len,
			const unsigned char *in, int in_len);
	virtual void priv_decrypt_batch(unsigned char **out, int *out_len,
			const unsigned char **in, const int *in_len,
			int n);

	/**
	 * Verify the signature with RSA algorithm using private key.
	 *
	 * @param m message.
	 * @param m_len message length.
	 * @param sigret Signature of the message.
	 * @param siglen Length of the signature.
	 */
	virtual int RSA_verify_message(unsigned char *m, unsigned int m_len,
    			unsigned char *sigbuf, unsigned int siglen);

	/**
	 *  Verify the signature with RSA algorithm using private key.
	 *
	 * @param m message.
	 * @param m_len message length.
	 * @param sigret Signature of the message.
	 * @param siglen Length of the signature.
	 * @param n Ciphertexts count.
	 */
	virtual int RSA_verify_message_batch(unsigned char *m, unsigned int m_len,
    			unsigned char *sigbuf, unsigned int siglen,
			int n);

protected:

private:
	void gpu_setup();

	RNS_CTX *rns_ctx[2];
};

#endif
