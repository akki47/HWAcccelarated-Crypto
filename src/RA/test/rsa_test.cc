/* This file includes test utilities for BN functions on device */
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <sys/time.h>
#include <unistd.h>

#include <typeinfo>

#include "mp_modexp.h"
#include "rsa_context.hh"
#include "rsa_context_rns.hh"
#include "rsa_context_mp.hh"
#include "common.hh"

void *__gxx_personality_v0;
static unsigned char ptext[rsa_context::max_batch][512];
static unsigned int ptext_len[rsa_context::max_batch];
static unsigned char ctext[rsa_context::max_batch][512];
static unsigned int ctext_len[rsa_context::max_batch];
//static unsigned char dtext[rsa_context::max_batch][512];
//static unsigned int dtext_len[rsa_context::max_batch];
static unsigned char condensedSignature[rsa_context::max_batch][512];

unsigned char ptext_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch][512];
unsigned int ptext_len_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char ctext_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch][512];
unsigned int ctext_len_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
//unsigned char dtext_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch][512];
//unsigned int dtext_len_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char *ctext_arr_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
//unsigned char *dtext_arr_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];
unsigned char *ptext_arr_str[rsa_context_mp::max_stream + 1][rsa_context::max_batch];

//static void test_correctness(rsa_context *rsa, int iteration)
//{
//    int max_len = rsa->get_key_bits() / 8;
//
//    /* step 1: no batch, static text */
//    printf("correctness check (no batch): ");
//    fflush(stdout);
//
//    ptext_len[0] = rand() % max_len;
//    ctext_len[0] = sizeof(ctext[0]);
//    dtext_len[0] = sizeof(dtext[0]);
//    set_random(ptext[0], ptext_len[0]);
//
//    rsa->pub_encrypt(ctext[0], &ctext_len[0], ptext[0], ptext_len[0]);
//    rsa->priv_decrypt(dtext[0], &dtext_len[0], ctext[0], ctext_len[0]);
//
//    assert(dtext_len[0] == ptext_len[0]);
//    assert(memcmp((char *)dtext[0], (char *)ptext[0], ptext_len[0]) == 0);
//
//    printf("OK\n");
//
//    /* step 2: no batch, random */
//    printf("correctness check (no batch, random, iterative): ");
//    fflush(stdout);
//
//    for (int k = 0; k < iteration; k++)
//    {
//        ptext_len[0] = (rand() % max_len);
//        ctext_len[0] = sizeof(ctext[0]);
//        dtext_len[0] = sizeof(dtext[0]);
//        set_random(ptext[0], ptext_len[0]);
//
//        rsa->pub_encrypt(ctext[0], &ctext_len[0], ptext[0], ptext_len[0]);
//        rsa->priv_decrypt(dtext[0], &dtext_len[0], ctext[0], ctext_len[0]);
//
//        assert(dtext_len[0] == ptext_len[0]);
//        assert(memcmp((char *)dtext[0], (char *)ptext[0], ptext_len[0]) == 0);
//        printf(".");
//        fflush(stdout);
//    }
//    printf("OK\n");
//
//    /* step 3: batch, random */
//    printf("correctness check (batch, random): ");
//    fflush(stdout);
//
//    bool all_correct = true;
//    for (int k = 1; k <= rsa_context::max_batch; k *= 2)
//    {
//        unsigned char *ctext_arr[rsa_context::max_batch];
//        unsigned char *dtext_arr[rsa_context::max_batch];
//
//        for (int i = 0; i < k; i++)
//        {
//            ptext_len[i] = rand() % max_len;
//            ctext_len[i] = sizeof(ctext[i]);
//            dtext_len[i] = sizeof(dtext[i]);
//            set_random(ptext[i], ptext_len[i]);
//
//            rsa->pub_encrypt(ctext[i], &ctext_len[i],
//                             ptext[i], ptext_len[i]);
//
//            dtext_arr[i] = dtext[i];
//            ctext_arr[i] = ctext[i];
//        }
//
//        rsa->priv_decrypt_batch((unsigned char **)dtext_arr, dtext_len,
//                                (const unsigned char **)ctext_arr, (const unsigned int *)ctext_len,
//                                k);
//
//        bool correct = true;
//        for (int i = 0; i < k; i++)
//        {
//            if (dtext_len[i] != ptext_len[i] ||
//            		memcmp((char *)dtext[i], (char *)ptext[i], ptext_len[i]) != 0)
//            {
//                correct = false;
//            }
//        }
//
//        if (correct)
//        {
//            printf(".");
//        }
//        else
//        {
//            printf("X");
//            all_correct = false;
//        }
//
//        fflush(stdout);
//    }
//
//    assert(all_correct);
//    printf("OK\n");
//}
//
//static void test_latency(rsa_context *rsa)
//{
//    bool warmed_up = false;
//    int max_len = rsa->max_ptext_bytes();
//
//    printf("# msg	latency(ms)	throughput(RSA msgs/s)\n");
//
//    for (int k = 1; k <= rsa_context::max_batch; k *= 2)
//    {
//        //if (k == 32)
//        //	k = 30; 	// GTX285 has 30 SMs :)
//
//        unsigned char *ctext_arr[rsa_context::max_batch];
//        unsigned char *dtext_arr[rsa_context::max_batch];
//
//        uint64_t begin;
//        uint64_t end;
//
//        for (int i = 0; i < k; i++)
//                {
//                    ptext_len[i] = rand() % max_len;
//                    ctext_len[i] = sizeof(ctext[i]);
//                    dtext_len[i] = sizeof(dtext[i]);
//                    set_random(ptext[i], ptext_len[i]);
//
//                    rsa->pub_encrypt(ctext[i], &ctext_len[i],
//                                     ptext[i], ptext_len[i]);
//
//                    dtext_arr[i] = dtext[i];
//                    ctext_arr[i] = ctext[i];
//                }
//
//again:
//        int iteration = 1;
//        begin = get_usec();
//try_more:
//
//
//        rsa->priv_decrypt_batch((unsigned char **)dtext_arr, dtext_len,
//                               (const unsigned char **)ctext_arr, (const unsigned int *)ctext_len,
//                                k);
//
//        end = get_usec();
//        if (end - begin < 300000)
//        {
//            for (int i = 0; i < k; i++)
//                dtext_len[i] = sizeof(dtext[i]);
//            iteration++;
//
//            if (!warmed_up)
//            {
//                warmed_up = true;
//                goto again;
//            }
//            else
//                goto try_more;
//        }
//
//        double total_time = (end - begin) / (iteration * 1000.0);
//        double throughput = (k * 1000000.0) * iteration / (end - begin);
//        printf("%4d\t%.2f\t\t%.2f\n",
//               k,
//               total_time,
//               throughput);
//    }
//}
//
//static void test_latency_stream(rsa_context_mp *rsa, device_context *dev_ctx, int concurrency)
//{
//    int max_len = rsa->max_ptext_bytes();
//
//    printf("# msg	throughput(RSA msgs/s)\n");
//
//    for (int k = 1; k <= rsa_context::max_batch; k *= 2)
//    {
//        //if (k == 32)
//        //	k = 30; 	// GTX285 has 30 SMs :)
//
//        uint64_t begin;
//        uint64_t end;
//
//        for (int s = 1; s <= concurrency; s++)
//        {
//            for (int i = 0; i < k; i++)
//            {
//                ptext_len_str[s][i] = (rand() % max_len + 1);
//                ctext_len_str[s][i] = sizeof(ctext_str[s][i]);
//                dtext_len_str[s][i] = sizeof(dtext_str[s][i]);
//                set_random(ptext_str[s][i], ptext_len_str[s][i]);
//
//                rsa->pub_encrypt(ctext_str[s][i], &ctext_len_str[s][i],
//                                 ptext_str[s][i], ptext_len_str[s][i]);
//
//                dtext_arr_str[s][i] = dtext_str[s][i];
//                ctext_arr_str[s][i] = ctext_str[s][i];
//            }
//        }
//
//        //warmup
//        for (int i = 1; i < concurrency; i++)
//        {
//            rsa->priv_decrypt_stream((unsigned char **)dtext_arr_str[i],
//                                     (unsigned int*)dtext_len_str[i],
//                                     (const unsigned char **)ctext_arr_str[i],
//                                     (const unsigned int*)ctext_len_str[i], k, i);
//            rsa->sync(i, true);
//        }
//
//        begin = get_usec();
//        int rounds = 50;
//        int count  = 0;
//        do
//        {
//            int stream = 0;
//            for (int i = 1; i <= concurrency; i++)
//            {
//                if (dev_ctx->get_state(i) == READY)
//                {
//                    stream = i;
//                    break;
//                }
//                else
//                {
//                    if (rsa->sync(i, false))
//                    {
//                        count++;
//                        if (count == concurrency)
//                            begin = get_usec();
//                    }
//                }
//            }
//            if (stream != 0)
//            {
//                rsa->priv_decrypt_stream((unsigned char **)dtext_arr_str[stream],
//                                         (unsigned int*)dtext_len_str[stream],
//                                         (const unsigned char **)ctext_arr_str[stream],
//                                         (const unsigned int *)ctext_len_str[stream], k, stream);
//            }
//            else
//            {
//                usleep(0);
//            }
//        }
//        while (count < rounds + concurrency);
//        end = get_usec();
//
//        for (int s = 1; s <= concurrency; s++)
//            rsa->sync(s, true);
//
//
//
//        double throughput = (k * 1000000.0) * (count - concurrency) / (end - begin);
//        printf("%4d *%2d\t%.2f\n",
//               k,
//               concurrency,
//               throughput);
//    }
//}
//
//static void sign_test_correctness(rsa_context *rsa, int siglen, int iteration)
//{
//    int max_len = rsa->max_ptext_bytes();
//    int signatureVerified = 0;
//
//    /* step 1: no batch, static text */
//    printf("correctness check (no batch): ");
//    fflush(stdout);
//
//    ptext_len[0] = siglen / 8;
//    ctext_len[0] = siglen / 8 ;
//    set_random(ptext[0], ptext_len[0]);
//
//    //strcpy((char *)ptext[0], "hello world, hello RSA");
//    //ptext_len[0] = strlen((char *)ptext[0]) + 1;
//
//    rsa->RSA_sign_message(ptext[0], ptext_len[0], ctext[0], (unsigned int)ctext_len[0]);
//    signatureVerified = rsa->RSA_verify_message(ptext[0], ptext_len[0], ctext[0], ctext_len[0]);
//
//    assert(signatureVerified == 1);
//
//    printf("OK\n");
//
//    /* step 2: no batch, random */
//    printf("correctness check (no batch, random, iterative): ");
//    fflush(stdout);
//
//    for (int k = 0; k < iteration; k++)
//    {
//        ptext_len[0] = siglen / 8; //(rand() % max_len) + 1;
//        ctext_len[0] = siglen / 8;
//        set_random(ptext[0], ptext_len[0]);
//
//        rsa->RSA_sign_message(ptext[0], ptext_len[0], ctext[0], (unsigned int)ctext_len[0]);
//
//        signatureVerified = 0;
//        signatureVerified = rsa->RSA_verify_message((unsigned char*)ptext[0], (unsigned int)ptext_len[0], ctext[0], (unsigned int)ctext_len[0]);
//
//        assert(signatureVerified == 1);
//
//        printf(".");
//        fflush(stdout);
//    }
//    printf("OK\n");
//
//    /* step 3: batch, random */
//    printf("correctness check (batch, random): ");
//    fflush(stdout);
//
//    bool all_correct = true;
//    for (int k = 1; k <= rsa_context::max_batch; k *= 2)
//    {
//        unsigned char *ctext_arr[rsa_context::max_batch];
//        unsigned char *ptext_arr[rsa_context::max_batch];
//
//        for (int i = 0; i < k; i++)
//        {
//            ptext_len[i] = siglen / 8; //(rand() % max_len) + 1;
//            ctext_len[i] = siglen / 8;
//            set_random(ptext[i], ptext_len[i]);
//
//
//            rsa->RSA_sign_message(ptext[i], ptext_len[i], ctext[i], (unsigned int)ctext_len[i]);
//
//            ptext_arr[i] = ptext[i];
//            ctext_arr[i] = ctext[i];
//        }
//
//        signatureVerified = 0;
//        signatureVerified = rsa->RSA_verify_message_batch((unsigned char **)ptext_arr, (unsigned int*)ptext_len,
//                                (const unsigned char **)ctext_arr, (unsigned int*)ctext_len,
//                                k);
//
//        bool correct = true;
//
//        if (!signatureVerified)
//        {
//        	correct = false;
//        }
//
//        if (correct)
//        {
//            printf(".");
//        }
//        else
//        {
//            printf("X");
//            all_correct = false;
//        }
//
//        fflush(stdout);
//    }
//
//    assert(all_correct);
//    printf("OK\n");
//}

static void sign_test_latency(rsa_context *rsa, int signature_len, int numberOfComponents)
{
    bool warmed_up = false;

    printf("# msg	lSOff(ms)	lSOn(us)	lVerify(us)	tSOff(RSA sigs/s)	tSOn(RA csigs/s)	tVerify(RA csigs/s)\n");

    for (int k = 64; k <= rsa_context::max_batch; k *= 2)
    {
        unsigned char *ptext_arr[rsa_context::max_batch];
        unsigned char *ctext_arr[rsa_context::max_batch];
        unsigned char *condensedSignature_arr[rsa_context::max_batch];

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

        beginSignOffline = get_usec();

        rsa->RA_sign_offline((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
                                        (unsigned char **)ctext_arr, (unsigned int*)ctext_len ,
                                        k);

        endSignOffline = get_usec();

againSign:
        int iterationSign = 1;
        beginSignOnline = get_usec();
try_moreSign:

		rsa->RA_sign_online((const unsigned char **)ctext_arr, (const unsigned int*)ctext_len,
				(unsigned char **)condensedSignature_arr, k, numberOfComponents);

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

		rsa->RA_verify((const unsigned char**)ptext_arr, (const unsigned int*)ptext_len,
				(const unsigned char**)condensedSignature_arr, k, numberOfComponents);

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

//void test_rsa_cpu()
//{
//    printf("------------------------------------------\n");
//    printf("RSA512, CPU, random\n");
//    printf("------------------------------------------\n");
//    rsa_context rsa512_cpu(512);
//    test_latency(&rsa512_cpu);
//    test_correctness(&rsa512_cpu, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, CPU, random\n");
//    printf("------------------------------------------\n");
//    rsa_context rsa1024_cpu(1024);
//    test_latency(&rsa1024_cpu);
//    test_correctness(&rsa1024_cpu, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA2048, CPU, random\n");
//    printf("------------------------------------------\n");
//    rsa_context rsa2048_cpu(2048);
//    test_latency(&rsa2048_cpu);
//    test_correctness(&rsa2048_cpu, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA4096, CPU, random\n");
//    printf("------------------------------------------\n");
//    rsa_context rsa4096_cpu(4096);
//    test_latency(&rsa4096_cpu);
//    test_correctness(&rsa4096_cpu, 20);
//}
//
//void test_rsa_rns()
//{
//    printf("------------------------------------------\n");
//    printf("RSA512, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa512_rns(512);
//    test_latency(&rsa512_rns);
//    test_correctness(&rsa512_rns, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa1024_rns(1024);
//    test_latency(&rsa1024_rns);
//    test_correctness(&rsa1024_rns, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA2048, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa2048_rns(2048);
//    test_latency(&rsa2048_rns);
//    test_correctness(&rsa2048_rns, 20);
//}
//
//void test_rsa_mp()
//{
//    device_context dev_ctx;
//    dev_ctx.init(10485760, 0);
//
//    printf("------------------------------------------\n");
//    printf("RSA512, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa512_mp(512);
//    rsa512_mp.set_device_context(&dev_ctx);
//    test_latency(&rsa512_mp);
//    test_correctness(&rsa512_mp, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa1024_mp(1024);
//    rsa1024_mp.set_device_context(&dev_ctx);
//    test_latency(&rsa1024_mp);
//    test_correctness(&rsa1024_mp, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA2048, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa2048_mp(2048);
//    rsa2048_mp.set_device_context(&dev_ctx);
//    test_latency(&rsa2048_mp);
//    test_correctness(&rsa2048_mp, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA4096, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa4096_mp(4096);
//    rsa4096_mp.set_device_context(&dev_ctx);
//    test_latency(&rsa4096_mp);
//    test_correctness(&rsa4096_mp, 20);
//}
//void test_rsa_mp_stream(unsigned num_stream)
//{
//    device_context dev_ctx;
//    dev_ctx.init(10485760, num_stream);
//
//    printf("------------------------------------------\n");
//    printf("RSA512, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa512_mp(512);
//    rsa512_mp.set_device_context(&dev_ctx);
//    test_latency_stream(&rsa512_mp, &dev_ctx, num_stream);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa1024_mp(1024);
//    rsa1024_mp.set_device_context(&dev_ctx);
//    test_latency_stream(&rsa1024_mp, &dev_ctx, num_stream);
//
//    printf("------------------------------------------\n");
//    printf("RSA2048, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa2048_mp(2048);
//    rsa2048_mp.set_device_context(&dev_ctx);
//    test_latency_stream(&rsa2048_mp, &dev_ctx, num_stream);
//
//    printf("------------------------------------------\n");
//    printf("RSA4096, GPU (MP), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa4096_mp(4096);
//    rsa4096_mp.set_device_context(&dev_ctx);
//    test_latency_stream(&rsa4096_mp, &dev_ctx, num_stream);
//}

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

//void sign_test_rsa_rns()
//{
//    printf("------------------------------------------\n");
//    printf("RSA512, SIGNATURE, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa512_rns(512);
//    sign_test_latency(&rsa512_rns, 512);
//    sign_test_correctness(&rsa512_rns, 512, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, SIGNATURE, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa1024_rns(1024);
//    sign_test_latency(&rsa1024_rns, 1024);
//    sign_test_correctness(&rsa1024_rns, 1024, 20);
//
//    printf("------------------------------------------\n");
//    printf("RSA2048, SIGNATURE, GPU (RNS), random\n");
//    printf("------------------------------------------\n");
//    rsa_context_rns rsa2048_rns(2048);
//    sign_test_latency(&rsa2048_rns, 2048);
//    sign_test_correctness(&rsa2048_rns, 2048, 20);
//}

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

//void test_rsa_mp_cert(unsigned num_stream)
//{
//    device_context dev_ctx;
//    dev_ctx.init(10485760, num_stream);
//
//    printf("------------------------------------------\n");
//    printf("RSA1024, GPU (MP), server.key\n");
//    printf("------------------------------------------\n");
//    rsa_context_mp rsa("../../server.key", "anlab");
//    rsa.set_device_context(&dev_ctx);
//    //rsa.dump();
//    if (num_stream == 0)
//    {
//        test_latency(&rsa);
//        test_correctness(&rsa, 20);
//    }
//    else
//    {
//        for (unsigned int i = 1; i <= 16; i++)
//            test_latency_stream(&rsa, &dev_ctx, i);
//    }
//}


static char usage[] = "Usage: %s -m MP,RNS,CPU [-s number of stream (MP-mode only)] \n";

int main(int argc, char *argv[])
{
    int rsa_sign = 0;
    int ntru_sign = 0;
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
    bool rns = false;
    bool cpu = false;
    int num_stream = 0;
    int i = 1;
    while (i < argc)
    {
        if (strcmp(argv[i], "-m") == 0)
        {
            i++;
            if (i == argc)
                goto parse_error;

            if (strcmp(argv[i], "MP") == 0)
            {
                mp = true;
            }
            else if (strcmp(argv[i], "RNS") == 0)
            {
                rns = true;
            }
            else if (strcmp(argv[i], "CPU") == 0)
            {
                cpu = true;
            }
            else
            {
                goto parse_error;
            }
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            if (!mp)
                goto parse_error;
            i++;
            if (i == argc)
                goto parse_error;
            num_stream = atoi(argv[i]);
            if (num_stream > 16 || num_stream < 0)
                goto parse_error;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            rsa_sign = 1;
        }
        else if (strcmp(argv[i], "-n") == 0)
        {
        	ntru_sign = 1;
        }
        else
        {
            goto parse_error;
        }
        i++;
    }

    if (!(mp || rns || cpu))
        goto parse_error;

    if(ntru_sign == 1)
    {




    }
    else if(ntru_sign == 0)
    {
    	//without ntru
    	//
    }
    else
    {
    	goto parse_error;
    }

    if(rsa_sign == 0)
    {
//        if (mp)
//        {
//            if (num_stream > 0)
//            {
//                test_rsa_mp_stream(num_stream);
//            }
//            else if (num_stream == 0)
//            {
//                test_rsa_mp();
//            }
//        }

//        if (rns)
//        {
//            test_rsa_rns();
//        }
//
//        if (cpu)
//        {
//            test_rsa_cpu();
//        }
    }
    else if (rsa_sign == 1)
    {
        if (mp)
        {
            if (num_stream > 0)
            {
            	//Not implemented for signature
            	assert(0);
                //sign_test_rsa_mp_stream(num_stream);
            }
            else if (num_stream == 0)
            {
                sign_test_rsa_mp();
            }
        }

        if (rns)
        {
            //sign_test_rsa_rns();
        }

        if (cpu)
        {
            sign_test_rsa_cpu();
        }
    }
    else
        goto parse_error;

    return 0;

parse_error:
    printf(usage, argv[0]);
    return -1;

#endif

}
