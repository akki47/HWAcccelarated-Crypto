#ifndef RSA_CONTEXT_HH
#define RSA_CONTEXT_HH

#include <string>
#include <stdlib.h>
#include <openssl/rsa.h>

/**
 * class rsa_context
 *
 * Interface for RSA processing.
 *
 */
class rsa_context
{
public:
	/**
	* Constructor.
	* It will randomly generate the RSA key pair with the given key length.
	*
	* @param keylen Length of key in bits. Supported length are 512, 1024, 2048, and 4096 bits.
	*/
	rsa_context(int keylen);

	/**
	 * Constructor.
	 * It will load key from the file using the given password.
	 * Currently supports PEM format only
	 *
	 * @param filename file path that contains the rsa private key
	 * @param passwd password used to encrypt the private key
	 */
	rsa_context(const std::string &filename, const std::string &passwd);

	/**
	 * Constructor.
	 * It will load key from the file using the given password.
	 * Currently supports PEM format only
	 *
	 * @param filename file path that contains the rsa private key
	 * @param passwd password used to encrypt the private key
	 */
	rsa_context(const char *filename, const char *passwd);

	virtual ~rsa_context();

	/**
	 * Return key length.
	 *
	 * @return key length in bits.
	 */
	int get_key_bits();

	/**
	 * Return a maximum amount of plain text that can be encrypted.
	 *
	 * @return maximum plain text size in bytes.
	 */
	int max_ptext_bytes();

	/**
	 * Return whether chinese remainder theorem (CRT) is used for processing or not.
	 *
	 * @return true if CRT is enabled, false otherwise.
	 */
	bool is_crt_available();

	virtual void dump();

	/**
	 * Encrypts the data with RSA algorithm using public key.
	 * All encryption/decryption methods assume RSA_PKCS1_PADDING
	 *
	 * @param out Buffer for output.
	 * @param out_len In: allocated buffer space for output result, Out: out put size.
	 * @param in Intput plain text.
	 * @param in_len Intpu plain text size.
	 */
	virtual void pub_encrypt(unsigned char *out, unsigned int *out_len,
			const unsigned char *in, unsigned int in_len);

	/**
	 * Decrypt the data with RSA algorithm using private key.
	 * All encryption/decryption methods assume RSA_PKCS1_PADDING
	 *
	 * @param out Buffer for output.
	 * @param out_len In: allocated buffer space for output result, Out: output size.
	 * @param in Buffer that stores cipher text.
	 * @param in_len Length of cipher text
	 */
	virtual void priv_decrypt(unsigned char *out, unsigned int *out_len,
			const unsigned char *in, unsigned int in_len);

	/**
	 * Decrypt the data with RSA algorithm using private key in a batch
	 * All encryption/decryption methods assume RSA_PKCS1_PADDING
	 *
	 * @param out Buffers for plain text.
	 * @param out_len In: allocated buffer space for output results, Out: output sizes.
	 * @param in Buffers that stores ciphertext.
	 * @param in_len Length of cipher texts.
	 * @param n Ciphertexts count.
	 */
	virtual void priv_decrypt_batch(unsigned char **out, unsigned int *out_len,
			const unsigned char **in, const unsigned int *in_len,
			int n);

	/**
	 * Generate RSA signatures of the given messages.
	 *
	 * @param sigbuf Signatures of the message.
	 * @param siglen Lengths of the signature.
	 * @param n Number of messages.
	 */
	virtual void RA_sign_offline(unsigned char **sigret, unsigned int *siglen);

	/**
	 * Generate a CondensedRSA signature using signature tables.
	 *
	 * @param m messages.
	 * @param m_len message lengths.
	 * @param sigbuf Signatures of the message.
	 * @param siglen Lengths of the signature.
	 * @param condensed_sig Returned condensed signature.
	 * @param n Number of messages.
	 */
	virtual void RA_sign_online(const unsigned char **m, const unsigned int *m_len, const unsigned char **sigbuf,
			const unsigned int *siglen, unsigned char **condensed_sig, int n);


	/**
	 *  Verify the condensed signature.
	 *
	 * @param m messages.
	 * @param m_len message lengths.
	 * @param condensed_sig Condensed signature.
	 * @param n Number of messages.
	 */
	virtual int RA_verify(const unsigned char **m, const unsigned int *m_len,const unsigned char **sigbuf,
			const unsigned int *siglen, const unsigned char **condensed_sig, int n);


	void CalculateMessageDigest(const unsigned char *m, unsigned int m_len,
			unsigned char *digest, unsigned int digestlen);

	float get_elapsed_ms_kernel();

	static const int max_batch = 2048 * 8 / 2;

	static const int numberOfSCRAChunks = 32;

	static const int maximumValueOfSCRAChunk = 256;

	RSA *rsa;

protected:
	void dump_bn(BIGNUM *bn, const char *name);

	// returns -1 if it fails
	int remove_padding(unsigned char *out, unsigned int *out_len, BIGNUM *bn);

	BN_CTX *bn_ctx;

	float elapsed_ms_kernel;

private:
	void set_crt();

	bool crt_available;
};

#endif
