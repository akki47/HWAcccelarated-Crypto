#ifndef __TEST_COMMON_HH__
#define __TEST_COMMON_HH__

#include <stdint.h>
#include <vector>

using namespace std;

uint64_t get_usec();
void set_random(unsigned char *buf, int len);

#endif /* __TEST_COMMON_HH__*/
