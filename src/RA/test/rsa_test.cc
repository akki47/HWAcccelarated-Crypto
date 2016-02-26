/* This file includes test utilities for BN functions on device */
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <typeinfo>

#include "mp_modexp.h"
#include "rsa_context.hh"
#include "rsa_context_mp.hh"
#include "common.hh"

int NUMTHREADS = 1;

void *__gxx_personality_v0;
static unsigned char ptext[rsa_context::max_batch][512];
static unsigned int ptext_len[rsa_context::max_batch];
static unsigned char ctext[rsa_context::max_batch][512];
static unsigned int ctext_len[rsa_context::max_batch];
static unsigned char condensedSignature[rsa_context::max_batch][512];

unsigned char ptext_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch][512];
unsigned int ptext_len_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char ctext_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch][512];
unsigned int ctext_len_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char *ctext_arr_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char *ptext_arr_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];

struct ThreadData {
	rsa_context *rsa;
	const unsigned char **m;
	const unsigned int *m_len;
	unsigned char **sigret;
	unsigned int *siglen;
	int n;
	int numberOfComponents;
};

void* createCPUThreads_RA_sign_offline(void* td) {
	struct ThreadData* data=(struct ThreadData*) td;
	data->rsa->RA_sign_offline(data->m, data->m_len, data->sigret, data->siglen , data->n);

	return NULL;
}

void* createCPUThreads_RA_sign_online(void* td) {
	struct ThreadData* data=(struct ThreadData*) td;
	data->rsa->RA_sign_online(data->m, data->m_len, data->sigret, data->n, data->numberOfComponents);

	return NULL;
}

void* createCPUThreads_RA_verify(void* td) {
	struct ThreadData* data=(struct ThreadData*) td;
	data->rsa->RA_verify(data->m, data->m_len, (const unsigned char**)data->sigret, data->n, data->numberOfComponents);

	return NULL;
}

static void sign_test_latency(rsa_context *rsa, int signature_len, int numberOfComponents)
{
	bool warmed_up = false;

	printf("# msg	lSOff(ms)	lSOn(us)	lVerify(us)	tSOff(RSA sigs/s)	tSOn(RA csigs/s)	tVerify(RA csigs/s)\n");

	for (int k = 64; k <= rsa_context::max_batch; k *= 2)
	{
		unsigned char *ptext_arr[rsa_context::max_batch];
		unsigned char *ctext_arr[rsa_context::max_batch];
		unsigned char *condensedSignature_arr[rsa_context::max_batch];
		struct ThreadData data[NUMTHREADS];
		pthread_t thread[NUMTHREADS];

		uint64_t beginSignOffline;
		uint64_t endSignOffline;
		uint64_t beginSignOnline;
		uint64_t endSignOnline;
		uint64_t beginVerify;
		uint64_t endVerify;

		for (int i = 0; i < k; i++)
		{
			ptext_len[i] = signature_len / 8;
			ctext_len[i] = signature_len / 8;

			set_random(ptext[i], ptext_len[i]);

			ptext_arr[i] = ptext[i];
			ctext_arr[i] = ctext[i];

			//if(i <= k - numberOfComponents)
			//{
			condensedSignature_arr[i] = condensedSignature[i];
			// }
		}
		int tasksPerThread=(k + NUMTHREADS-1)/NUMTHREADS;

		beginSignOffline = get_usec();

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {
			data[i].rsa = rsa;
			data[i].m = (const unsigned char**)(ptext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ptext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(ctext_arr + i*tasksPerThread);
			data[i].siglen = (unsigned int*)(ctext_len + i*tasksPerThread);
			data[i].n = tasksPerThread;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//		rsa->RA_sign_offline((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
		//				(unsigned char **)ctext_arr, (unsigned int*)ctext_len ,
		//				k);

		endSignOffline = get_usec();

		againSign:
		int iterationSign = 1;
		beginSignOnline = get_usec();
		try_moreSign:

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {
			data[i].rsa = rsa;
			data[i].m = (const unsigned char**)(ctext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ctext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(condensedSignature_arr + i*tasksPerThread);
			data[i].n = tasksPerThread;
			data[i].numberOfComponents = numberOfComponents;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//rsa->RA_sign_online((const unsigned char **)ctext_arr, (const unsigned int*)ctext_len,
		//		(unsigned char **)condensedSignature_arr, k, numberOfComponents);

		endSignOnline = get_usec();
		if (iterationSign < 25)
		{
			iterationSign++;

			if (!warmed_up)
			{
				warmed_up = true;
				goto againSign;
			}
			else
				goto try_moreSign;
		}

		warmed_up = false;

		againVerify:
		int iterationVerify = 1;
		beginVerify = get_usec();
		try_moreVerify:

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {
			data[i].rsa = rsa;
			data[i].m = (const unsigned char**)(ptext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ptext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(condensedSignature_arr + i*tasksPerThread);
			data[i].n = tasksPerThread;
			data[i].numberOfComponents = numberOfComponents;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//rsa->RA_verify((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
		//		(const unsigned char**)condensedSignature_arr, k, numberOfComponents);

		endVerify = get_usec();
		if (iterationVerify < 25)
		{
			iterationVerify++;

			if (!warmed_up)
			{
				warmed_up = true;
				goto againVerify;
			}
			else
				goto try_moreVerify;
		}


		double total_time_sign_offline = (endSignOffline - beginSignOffline) / 1000.0;
		double throughput_sign_offline = (k * 1000000.0) / (endSignOffline - beginSignOffline);

		double total_time_sign_online = (endSignOnline - beginSignOnline) / (iterationSign);
		double throughput_sign_online = ((k - numberOfComponents) * 1000000.0) * iterationSign / (endSignOnline - beginSignOnline);

		double total_time_verify = (endVerify - beginVerify) / (iterationVerify);
		double throughput_verify = ((k - numberOfComponents) * 1000000.0) * iterationVerify / (endVerify - beginVerify);

		printf("%4d\t%.2f\t\t%.2f\t\t%.2f\t\t%.2f\t\t\t%.2f\t\t\t%.2f\n",
				k,
				total_time_sign_offline,
				total_time_sign_online,
				total_time_verify,
				throughput_sign_offline,
				throughput_sign_online,
				throughput_verify);
	}
}

static void sign_test_latency_DynamicScheduler(rsa_context *cpu_rsa,  rsa_context *gpu_rsa, int signature_len, int numberOfComponents)
{
	bool warmed_up = false;

	//Adding one thread for the GPU processing
	//NUMTHREADS++;

	printf("# msg	lSOff(ms)	lSOn(us)	lVerify(us)	tSOff(RSA sigs/s)	tSOn(RA csigs/s)	tVerify(RA csigs/s)\n");

	for (int k = 64; k <= rsa_context::max_batch; k *= 2)
	{
		unsigned char *ptext_arr[rsa_context::max_batch];
		unsigned char *ctext_arr[rsa_context::max_batch];
		unsigned char *condensedSignature_arr[rsa_context::max_batch];
		struct ThreadData data[NUMTHREADS];
		pthread_t thread[NUMTHREADS];

		uint64_t beginSignOffline;
		uint64_t endSignOffline;
		uint64_t beginSignOnline;
		uint64_t endSignOnline;
		uint64_t beginVerify;
		uint64_t endVerify;

		for (int i = 0; i < k; i++)
		{
			ptext_len[i] = signature_len / 8;
			ctext_len[i] = signature_len / 8;

			set_random(ptext[i], ptext_len[i]);

			ptext_arr[i] = ptext[i];
			ctext_arr[i] = ctext[i];

			//if(i <= k - numberOfComponents)
			//{
			condensedSignature_arr[i] = condensedSignature[i];
			// }
		}
		int tasksPerThread=(k + NUMTHREADS-1)/NUMTHREADS;

		beginSignOffline = get_usec();

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {

			if(i == 0)
				data[i].rsa = gpu_rsa;
			else
				data[i].rsa = cpu_rsa;

			data[i].m = (const unsigned char**)(ptext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ptext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(ctext_arr + i*tasksPerThread);
			data[i].siglen = (unsigned int*)(ctext_len + i*tasksPerThread);
			data[i].n = tasksPerThread;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//		rsa->RA_sign_offline((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
		//				(unsigned char **)ctext_arr, (unsigned int*)ctext_len ,
		//				k);

		endSignOffline = get_usec();

		againSign:
		int iterationSign = 1;
		beginSignOnline = get_usec();
		try_moreSign:

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {
			if(i == 0)
				data[i].rsa = gpu_rsa;
			else
				data[i].rsa = cpu_rsa;
			data[i].m = (const unsigned char**)(ctext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ctext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(condensedSignature_arr + i*tasksPerThread);
			data[i].n = tasksPerThread;
			data[i].numberOfComponents = numberOfComponents;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//rsa->RA_sign_online((const unsigned char **)ctext_arr, (const unsigned int*)ctext_len,
		//		(unsigned char **)condensedSignature_arr, k, numberOfComponents);

		endSignOnline = get_usec();
		if (iterationSign < 25)
		{
			iterationSign++;

			if (!warmed_up)
			{
				warmed_up = true;
				goto againSign;
			}
			else
				goto try_moreSign;
		}

		warmed_up = false;

		againVerify:
		int iterationVerify = 1;
		beginVerify = get_usec();
		try_moreVerify:

		/* Divide work for threads, prepare parameters */
		for (int i=0; i<NUMTHREADS; i++) {
			if(i == 0)
				data[i].rsa = gpu_rsa;
			else
				data[i].rsa = cpu_rsa;
			data[i].m = (const unsigned char**)(ptext_arr + i*tasksPerThread);
			data[i].m_len = (const unsigned int*)(ptext_len + i*tasksPerThread);
			data[i].sigret = (unsigned char **)(condensedSignature_arr + i*tasksPerThread);
			data[i].n = tasksPerThread;
			data[i].numberOfComponents = numberOfComponents;
		}

		/* Launch Threads */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_create(&thread[i], NULL, createCPUThreads_RA_sign_offline, &data[i]);
		}

		/* Wait for Threads to Finish */
		for (int i=0; i<NUMTHREADS; i++) {
			pthread_join(thread[i], NULL);
		}

		//rsa->RA_verify((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
		//		(const unsigned char**)condensedSignature_arr, k, numberOfComponents);

		endVerify = get_usec();
		if (iterationVerify < 25)
		{
			iterationVerify++;

			if (!warmed_up)
			{
				warmed_up = true;
				goto againVerify;
			}
			else
				goto try_moreVerify;
		}


		double total_time_sign_offline = (endSignOffline - beginSignOffline) / 1000.0;
		double throughput_sign_offline = (k * 1000000.0) / (endSignOffline - beginSignOffline);

		double total_time_sign_online = (endSignOnline - beginSignOnline) / (iterationSign);
		double throughput_sign_online = ((k - numberOfComponents) * 1000000.0) * iterationSign / (endSignOnline - beginSignOnline);

		double total_time_verify = (endVerify - beginVerify) / (iterationVerify);
		double throughput_verify = ((k - numberOfComponents) * 1000000.0) * iterationVerify / (endVerify - beginVerify);

		printf("%4d\t%.2f\t\t%.2f\t\t%.2f\t\t%.2f\t\t\t%.2f\t\t\t%.2f\n",
				k,
				total_time_sign_offline,
				total_time_sign_online,
				total_time_verify,
				throughput_sign_offline,
				throughput_sign_online,
				throughput_verify);
	}
}

void sign_test_rsa_cpu()
{
	int numberOfComponents = 32;
	printf("------------------------------------------\n");
	printf("RSA512, SIGNATURE, CPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa512_cpu(512);
	sign_test_latency(&rsa512_cpu, 512, numberOfComponents);
	//sign_test_correctness(&rsa512_cpu, 512, 20);

	printf("------------------------------------------\n");
	printf("RSA1024, SIGNATURE, CPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa1024_cpu(1024);
	sign_test_latency(&rsa1024_cpu, 1024, numberOfComponents);
	//sign_test_correctness(&rsa1024_cpu, 1024, 20);

	printf("------------------------------------------\n");
	printf("RSA2048, SIGNATURE, CPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa2048_cpu(2048);
	sign_test_latency(&rsa2048_cpu, 2048, numberOfComponents);
	//sign_test_correctness(&rsa2048_cpu, 2048, 20);

	printf("------------------------------------------\n");
	printf("RSA4096, SIGNATURE, CPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa4096_cpu(4096);
	sign_test_latency(&rsa4096_cpu, 4096, numberOfComponents);
	//sign_test_correctness(&rsa4096_cpu, 4096, 20);
}

void sign_test_rsa_mp()
{
	int numberOfComponents = 32;
	device_context dev_ctx;
	dev_ctx.init(10485760, 0);

	printf("------------------------------------------\n");
	printf("RSA512, SIGNATURE, GPU (MP), random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context_mp rsa512_mp(512);
	rsa512_mp.set_device_context(&dev_ctx);
	sign_test_latency(&rsa512_mp, 512, numberOfComponents);
	//sign_test_correctness(&rsa512_mp, 512, 20);

	printf("------------------------------------------\n");
	printf("RSA1024, SIGNATURE, GPU (MP), random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context_mp rsa1024_mp(1024);
	rsa1024_mp.set_device_context(&dev_ctx);
	sign_test_latency(&rsa1024_mp, 1024, numberOfComponents);
	//sign_test_correctness(&rsa1024_mp, 1024, 20);

	printf("------------------------------------------\n");
	printf("RSA2048, SIGNATURE, GPU (MP), random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context_mp rsa2048_mp(2048);
	rsa2048_mp.set_device_context(&dev_ctx);
	sign_test_latency(&rsa2048_mp, 2048, numberOfComponents);
	//sign_test_correctness(&rsa2048_mp, 2048,  20);

	//    printf("------------------------------------------\n");
	//    printf("RSA4096, SIGNATURE, GPU (MP), random, NumberOfComponents=%d\n", numberOfComponents);
	//    printf("------------------------------------------\n");
	//    rsa_context_mp rsa4096_mp(4096);
	//    rsa4096_mp.set_device_context(&dev_ctx);
	//    sign_test_latency(&rsa4096_mp, 4096, numberOfComponents);
	//    //sign_test_correctness(&rsa4096_mp, 4096, 20);
}

void sign_test_rsa_DynamicScheduler()
{
	int numberOfComponents = 32;
	device_context dev_ctx;
	dev_ctx.init(10485760, 0);

	printf("------------------------------------------\n");
	printf("RSA512, SIGNATURE, CPU+GPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa512_cpu(512);
	rsa_context_mp rsa512_mp(512);
	rsa512_mp.set_device_context(&dev_ctx);

	sign_test_latency_DynamicScheduler(&rsa512_cpu, &rsa512_mp, 512, numberOfComponents);
	//sign_test_correctness(&rsa512_cpu, 512, 20);

	printf("------------------------------------------\n");
	printf("RSA1024, SIGNATURE, CPU+GPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa1024_cpu(1024);
	rsa_context_mp rsa1024_mp(1024);
	rsa1024_mp.set_device_context(&dev_ctx);

	sign_test_latency_DynamicScheduler(&rsa1024_cpu, &rsa1024_mp, 1024, numberOfComponents);
	//sign_test_correctness(&rsa1024_cpu, 1024, 20);

	printf("------------------------------------------\n");
	printf("RSA2048, SIGNATURE, CPU+GPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa2048_cpu(2048);
	rsa_context_mp rsa2048_mp(2048);
	rsa2048_mp.set_device_context(&dev_ctx);

	sign_test_latency_DynamicScheduler(&rsa2048_cpu, &rsa2048_mp, 2048, numberOfComponents);
	//sign_test_correctness(&rsa2048_cpu, 2048, 20);

	printf("------------------------------------------\n");
	printf("RSA4096, SIGNATURE, CPU+GPU, random, NumberOfComponents=%d\n", numberOfComponents);
	printf("------------------------------------------\n");
	rsa_context rsa4096_cpu(4096);
	rsa_context_mp rsa4096_mp(4096);
	rsa4096_mp.set_device_context(&dev_ctx);

	sign_test_latency_DynamicScheduler(&rsa4096_cpu, &rsa4096_mp, 4096, numberOfComponents);
	//sign_test_correctness(&rsa4096_cpu, 4096, 20);
}

static char usage[] = "Usage: %s -m [MP/CPU/DS] -n numberOfThreads\n";

int main(int argc, char *argv[])
{
	srand(time(NULL));
#if 0
	int count = 0;

	while (1)
	{
		mp_test_cpu();
		mp_test_gpu();

		count++;
		if (count % 1 == 0)
			printf("%d times...\n", count);
	}
#else
	bool mp  = false;
	bool cpu = false;
	bool ds = false;
	int i = 1;
	while (i < argc)
	{
		if (strcmp(argv[i], "-m") == 0)
		{
			i++;
			if (i == argc)
				goto parse_error;

			if (strcmp(argv[i], "MP") == 0)
				mp = true;
			else if (strcmp(argv[i], "CPU") == 0)
				cpu = true;
			else if (strcmp(argv[i], "DS") == 0)
				ds = true;
			else
				goto parse_error;

		}else if(strcmp(argv[i], "-n") == 0)
		{
			i++;
			if (i == argc)
				goto parse_error;

			NUMTHREADS = atoi(argv[i]);
		}else
			goto parse_error;

		i++;
	}

	if (!(mp || cpu || ds))
		goto parse_error;


	if (mp)
		sign_test_rsa_mp();
	else if(cpu)
		sign_test_rsa_cpu();
	else if(ds)
		sign_test_rsa_DynamicScheduler();
	else
		goto parse_error;

	return 0;

	parse_error:
	printf(usage, argv[0]);
	return -1;

#endif

}
