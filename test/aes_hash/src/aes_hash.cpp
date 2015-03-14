//============================================================================
// Name        : aes_hash.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include "base64.h"
#include "Crypto.h"
#include <string>
#include <sstream>
#include <cassert>
#define PRINT_KEYS
using namespace std;

float elapsed_time[10];

float test_encrypt_aes_cbc_CPU(unsigned int key_bits, unsigned int  num_flows,unsigned int flow_len)
{
	Crypto crypto;
	unsigned int msg2_length = flow_len;
	//cout<<endl<<msg2_length<<endl;
	unsigned int encMsg2Len;
	unsigned char *encMsg2 = NULL;
	unsigned char *msg2 = new unsigned char[msg2_length];
	RAND_bytes(msg2,msg2_length);

	unsigned char *k_0 = new unsigned char[16];
	memcpy(k_0,"0000000000000000",16);

	crypto.setAESKey(k_0,16);
	unsigned int i=0;
	int x=0;
	clock_t begin = clock();
	while(x<num_flows)
	{
		i=0;
	while(i<(msg2_length))
	{
	if((encMsg2Len = crypto.aesEncrypt((const unsigned char*)msg2+i, 16, &encMsg2)) == -1) {
		fprintf(stderr, "Encryption failed\n");
		return 1;
		}
	unsigned char *msg3 = new unsigned char[16];
	for(int m=0;m<16;m++)
	{
		msg3[m] = k_0[m] ^ encMsg2[m];
	}
	memcpy(k_0,msg3,16);
	i = i+16;
	}

	//cout<<endl<<"No of messages:"<<x+1<<endl;
	x++;
	}
	clock_t end = clock();
	float tt = difftime(end,begin)/CLOCKS_PER_SEC;
	//cout<<endl<<"time taken:"<<difftime(end,begin)*1000/CLOCKS_PER_SEC<<endl;
	return tt;

	}

float test_encrypt_sha_CPU(unsigned int key_bits, unsigned int  num_flows,unsigned int flow_len)
{
	Crypto crypto;
	unsigned int msg2_length = flow_len;
	//cout<<endl<<msg2_length<<endl;
	unsigned int encMsg2Len;
	unsigned char *encMsg2 = NULL;
	unsigned char *msg2 = new unsigned char[msg2_length];
	unsigned char *digest = new unsigned char[20];
	RAND_bytes(msg2,msg2_length);

	unsigned int i=0;
	int x=0;
	clock_t begin = clock();
	while(x<num_flows)
	{
		i=0;
	SHA_CTX sha_ctx = { 0 };
	int rc = 1;

	rc = SHA1_Init(&sha_ctx);
	assert(rc ==1);

	rc = SHA1_Update(&sha_ctx, msg2, msg2_length);
	assert(rc ==1);

	rc = SHA1_Final(digest, &sha_ctx);
	assert(rc ==1);

	//cout<<endl<<"No of messages:"<<x+1<<endl;
	x++;
	}
	clock_t end = clock();
	float tt = difftime(end,begin)/CLOCKS_PER_SEC;
	//cout<<endl<<"time taken:"<<difftime(end,begin)*1000/CLOCKS_PER_SEC<<endl;
	return tt;

	}


int aes_128_test_latency_CPU(unsigned int key_bits,unsigned int num_flows,unsigned int flow_len)
{
	unsigned rounds = 10;

	int results =0;

	for (unsigned i = 0; i < rounds; i++ ) {
		//gpu execution
		clock_t begin = clock();
		//cout<<endl<<"running for round"<<i<<endl;
		float tt;
		tt=test_encrypt_aes_cbc_CPU(key_bits, num_flows,flow_len);
		clock_t end = clock();
		//cout<<endl<<double(end-begin)/CLOCKS_PER_SEC<<endl;
		elapsed_time[i] = tt;
		//cout<<endl<<elapsed_time[i]<<endl;
	}

	 float total = 0;
	float avg = 0;
	for (unsigned i = 0; i <rounds; i++)
		total += elapsed_time[i];
	avg = total / rounds;

	printf("%4d %13lf %13lf\n",num_flows, avg*1000,num_flows * flow_len * 8 / (avg*1000000));
	return 0;

}

int sha_128_test_latency_CPU(unsigned int key_bits,unsigned int num_flows,unsigned int flow_len)
{
	unsigned rounds = 10;

	int results =0;

	for (unsigned i = 0; i < rounds; i++ ) {
		//gpu execution
		clock_t begin = clock();
		//cout<<endl<<"running for round"<<i<<endl;
		float tt;
		tt=test_encrypt_sha_CPU(key_bits, num_flows,flow_len);
		clock_t end = clock();
		//cout<<endl<<double(end-begin)/CLOCKS_PER_SEC<<endl;
		elapsed_time[i] = tt;
		//cout<<endl<<elapsed_time[i]<<endl;
	}

	 float total = 0;
	float avg = 0;
	for (unsigned i = 0; i <rounds; i++)
		total += elapsed_time[i];
	avg = total / rounds;

	printf("%4d %13lf %13lf\n",num_flows, avg*1000,num_flows * flow_len * 8 / (avg*1000000));
	return 0;

}

static char usage[] = "Usage: %s AES,SHA [-l length of message in bytes (multiples of 16)]\n";

int main(int argc, char *argv[]) {

	unsigned int size=16384;
	int i = 1;

	while (i < argc)
	{
		if (strcmp(argv[i], "AES") == 0)
		{
			printf("------------------------------------------\n");
			printf("AES-128-HASH ENC CPU, Size: %dKB\n", size / 1024);
			printf("------------------------------------------\n");
			printf("#msg latency(ms) thruput(Mbps)\n");
			for (unsigned i = 1; i <= 4096;  i *= 2)
				aes_128_test_latency_CPU(128, i, size);
			printf("OK\n");
		}
		else if(strcmp(argv[i], "SHA") == 0)
		{
			printf("------------------------------------------\n");
			printf("SHA1-HASH CPU, Size: %dKB\n", size / 1024);
			printf("------------------------------------------\n");
			printf("#msg latency(ms) thruput(Mbps)\n");
			for (unsigned i = 1; i <= 4096;  i *= 2)
				sha_128_test_latency_CPU(128, i, size);
			printf("OK\n");
		}
		else if(strcmp(argv[i], "-l") == 0)
		{
			i++;
			if (i == argc)
				goto parse_error;
			size = atoi(argv[i]);
			if (size <= 0 || size > 16384 || size % 16 != 0)
				goto parse_error;
		}
		else
		{
			goto parse_error;
		}
		i++;
	}

	return 0;

parse_error:
	printf(usage, argv[0]);
	return -1;

}
