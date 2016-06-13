// Boneh-Lynn-Shacham short signatures demo.
//
// See the PBC_sig library for a practical implementation.
//
// Ben Lynn
#include <pbc.h>
#include <pbc_test.h>
#include <time.h>

#define NO_MESS 8192
#define maximumValueOfSCRAChunk 256
#define numberOfSCRAChunks 20

int main(int argc, char **argv) {
	pairing_t pairing;
	element_t g, h;
	element_t s[NO_MESS],sigma[NO_MESS],sigma_ver[NO_MESS];
	element_t public_key, sig;
	element_t secret_key;
	element_t temp1, temp2,temp3[NO_MESS],temp4[NO_MESS];
	int i,j,k;
	clock_t c0,c1,off0,off1,on0,on1,ver1,ver0,wsig0,wsig1,wver0,wver1;
	float scra,ver,on;
	int trials=0;

	element_t digest[maximumValueOfSCRAChunk * numberOfSCRAChunks];
	element_t hashes[maximumValueOfSCRAChunk * numberOfSCRAChunks];

	printf("\n#msg \t without SCRA sign \t without SCRA verify \t Offline Stage \t Online Stage \t Verify Stage \t With SCRA");

	for(k=32;k<=NO_MESS;(k=k*2))
	{
		pbc_demo_pairing_init(pairing, argc, argv);

		element_init_G2(g, pairing);
		element_init_G2(public_key, pairing);
		element_init_G1(h, pairing);
		element_init_G1(sig, pairing);
		element_init_GT(temp1, pairing);
		element_init_GT(temp2, pairing);
		element_init_Zr(secret_key, pairing);

		for(i=0;i<k;i++)
		{
			element_init_G1(sigma[i], pairing);
		}

		for(i=0;i<(numberOfSCRAChunks*maximumValueOfSCRAChunk);i++)
		{
			element_init_G1(digest[i], pairing);
			element_init_G1(hashes[i], pairing);
		}

		for(i=0;i<k;i++)
		{
			element_init_G1(s[i], pairing);
			element_init_GT(temp3[i], pairing);
			element_init_G1(sigma_ver[i], pairing);
			element_init_GT(temp4[i], pairing);
		}

		//generate system parameters
		element_random(g);
		//element_printf("system parameter g = %B\n", g);

		//generate private key
		element_random(secret_key);
		//element_printf("private key = %B\n", secret_key);

		//compute corresponding public key
		element_pow_zn(public_key, g, secret_key);
		//element_printf("public key = %B\n", public_key);

		//generate element from a hash
		//for toy pairings, should check that pairing(g, h) != 1
		element_from_hash(h, "hashofmessage", 13);
		element_printf("message hash = %B\n", h);

		//printf("Short signature test\n");

		//  //offline phase
		//	  off0 = clock();
		for(i=0;i<k;i++)
		{
			//h^secret_key is the signature
			//in real life: only output the first coordinate
			element_pow_zn(s[i], h, secret_key);
			//element_pow_zn(sig, h, secret_key);
			//element_printf("signature = %B\n", s[i]);
			//printf("%d\n",i);
		}
		//  off1 = clock();
		//  //offline phase end

		//offline phase
		int buffer;
		unsigned char in[256];
		off0 = clock();
		trials=0;
		while(trials<1)
		{
			for(i=0;i<numberOfSCRAChunks;i++)
			{
				for(j=0;j<maximumValueOfSCRAChunk;j++)
				{
					//h^secret_key is the signature
					//in real life: only output the first coordinate
					buffer =0;
					buffer = buffer | (i << (sizeof(int) * 8 - 5));
					buffer = buffer | (j << (sizeof(int) * 8 - 13));

					memset(in,0,sizeof(in));
					snprintf(in, sizeof(in),"%d",buffer);

					element_from_hash(hashes[(i*maximumValueOfSCRAChunk)+j],in, 13);
					element_pow_zn(digest[(i*maximumValueOfSCRAChunk)+j], hashes[(i*maximumValueOfSCRAChunk)+j], secret_key);
					//element_pow_zn(sig, h, secret_key);
					//element_printf("signature = %B\n", s[i]);
					//printf("%d\n",i);
				}
			}
			trials++;
		}
		off1 = clock();

		//printf("Offline Stage complete");

		for(i=0;i<k;i++)
		{
			//h^secret_key is the signature
			//in real life: only output the first coordinate
			element_pow_zn(s[i], h, secret_key);
			//element_pow_zn(sig, h, secret_key);
			//element_printf("signature = %B\n", s[i]);
			//printf("%d\n",i);
		}

		//offline phase end

		//without SCRA
		c0 = clock();
		trials=0;
		wsig0 = clock();
		while(trials<1)
		{

			for(i=0;i<k-numberOfSCRAChunks;i++)
			{
				//h^secret_key is the signature
				//in real life: only output the first coordinate
				element_pow_zn(s[i], h, secret_key);
				//element_pow_zn(sig, h, secret_key);
				//element_printf("signature = %B\n", s[i]);
				//printf("%d\n",i);
			}
			trials++;
		}
		wsig1 = clock();
		wver0 = clock();
		trials=0;
		while(trials < 1)
		{
			for(i=0;i<k-numberOfSCRAChunks;i++)
			{
				element_pairing(temp1, s[i], g);
				// element_printf("f(sig, g) = %B\n", temp1);

				//verification part 2
				//should match above
				element_pairing(temp2, h, public_key);
				//element_printf("f(message hash, public_key) = %B\n", temp2);

				if (!element_cmp(temp1, temp2)) {
					//printf("signature verifies\n");
				} else {
					printf("*BUG* without scra signature does not verify *BUG*\n");
				}

			}

			trials++;
		}
		wver1 = clock();
		c1 = clock();

		//without SCRA end

		//online phase
		on0 = clock();
		trials=0;
		while(trials<1)
		{
			for(i=0;i<(k-numberOfSCRAChunks);i++)
			{
				element_init_same_as(sigma[i],digest[maximumValueOfSCRAChunk]);

				for(j=1;j<numberOfSCRAChunks;j++)
				{
					int offset = in[j] - '0';
					element_mul(sigma[i], sigma[i], digest[(j*maximumValueOfSCRAChunk)+offset]);
				}
			}
			trials++;
		}
		on1 = clock();
		//online phase end



		{
			int n = pairing_length_in_bytes_compressed_G1(pairing);
			//int n = element_length_in_bytes_compressed(sig);
			int i;
			unsigned char *data = pbc_malloc(n);

			element_to_bytes_compressed(data, sig);
			//printf("compressed = ");
			for (i = 0; i < n; i++) {
				// printf("%02X", data[i]);
			}
			//printf("\n");

			element_from_bytes_compressed(sig, data);
			//element_printf("decompressed = %B\n", sig);

			pbc_free(data);
		}

		//verification phase

		ver0 = clock();
		trials=0;
		while(trials<1)
		{
			//verification part 1
			//element_from_hash(h,in, 13);

			for(i=0;i<(k-numberOfSCRAChunks);i++)
			{
				//printf("wtf\n\n");


				//element_pairing(temp1, sig, g);
				element_pairing(temp4[i], sigma[i], g);
				//element_printf("f(sig, g) = %B\n", temp4);

				//verification part 2
				//should match above
				//element_pairing(temp3[i], h, public_key);
				element_init_same_as(sigma_ver[i],hashes[maximumValueOfSCRAChunk]);

				for(j=1;j<numberOfSCRAChunks;j++)
				{
					//element_pairing(temp3[i+j], h, public_key);
					int offset = in[j] - '0';
					element_mul(sigma_ver[i], sigma_ver[i], hashes[(j*maximumValueOfSCRAChunk)+offset]);
				}

				element_pairing(temp2, sigma_ver[i], public_key);
				//element_printf("f(message hash, public_key) = %B\n", sigma_ver);

				//  if (!element_cmp(temp1, temp2)) {
				//    printf("signature verifies\n");
				//  } else {
				//    printf("*BUG* signature does not verify *BUG*\n");
				//  }
				if (!element_cmp(temp2, temp4[i])) {
					// printf("signature verifies\n");
				} else {
					printf("*BUG* aggregate signature does not verify *BUG*\n");
				}
				//element_clear(temp4[]);
				//element_clear(sigma_ver);
			}
			trials++;
		}
		ver1 = clock();
		//verification end
		{
			int n = pairing_length_in_bytes_x_only_G1(pairing);
			//int n = element_length_in_bytes_x_only(sig);
			int i;
			unsigned char *data = pbc_malloc(n);

			element_to_bytes_x_only(data, sig);
			//printf("x-coord = ");
			for (i = 0; i < n; i++) {
				//printf("%02X", data[i]);
			}
			// printf("\n");

			element_from_bytes_x_only(sig, data);
			//element_printf("de-x-ed = %B\n", sig);

			//    element_pairing(temp1, sig, g);
			//    if (!element_cmp(temp1, temp2)) {
			//      printf("signature verifies on first guess\n");
			//    } else {
			//      element_invert(temp1, temp1);
			//      if (!element_cmp(temp1, temp2)) {
			//        printf("signature verifies on second guess\n");
			//      } else {
			//        printf("*BUG* signature does not verify *BUG*\n");
			//      }
			//    }

			pbc_free(data);
			ver = (((float)(ver1 - ver0)/(CLOCKS_PER_SEC))/(k-numberOfSCRAChunks))/trials;
			on = (((float)(on1 - on0)/(CLOCKS_PER_SEC))/(k-numberOfSCRAChunks))/trials;
			printf("\n%4d\t\t%.10f\t\t%.10f\t\t%.10f\t\t%.10f\t\t%.10f\t\t%.10f\t\t\n",k,(((float) (wsig1 - wsig0)/(CLOCKS_PER_SEC))/(k-numberOfSCRAChunks))/trials,(((float) (wver1 - wver0)/(CLOCKS_PER_SEC))/(k-numberOfSCRAChunks))/trials,(((float) (off1 - off0)/(CLOCKS_PER_SEC)))/trials,on,ver, (on+ver));
		}

		//a random signature shouldn't verify
		element_random(sig);
		element_pairing(temp1, sig, g);
		if (element_cmp(temp1, temp2)) {
			// printf("random signature doesn't verify\n");
		} else {
			printf("*BUG* random signature verifies *BUG*\n");
		}

		element_clear(sig);
		element_clear(public_key);
		element_clear(secret_key);
		element_clear(g);
		element_clear(h);
		element_clear(temp1);
		element_clear(temp2);
		pairing_clear(pairing);
	}
	return 0;
}
