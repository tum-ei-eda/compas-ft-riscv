/* Exercise the application CRC kernel without its C library and simulator I/O. */
#include "../../apps/crc/crc.h"

volatile int crc_lengths[] = {-1, 0, 1, 3, 9};
static const unsigned char crc_message[] = "123456789";

int main(void)
{
    /* Independent CRC-CCITT literals for no bytes and the 1/3/9-byte prefixes. */
    static const crc expected[] = {0xffff, 0xffff, 0xc782, 0x5bce, 0x29b1};
    unsigned int repeat;
    for (repeat = 0; repeat != 2; ++repeat) {
        unsigned int index;
        for (index = 0; index != 5; ++index) {
            if (crcSlow(crc_message, crc_lengths[index]) != expected[index])
                return 17;
        }
    }
    return 42;
}
