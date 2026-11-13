#include "rounding.h"

volatile round_value round_first;
volatile round_value round_second;

/* Four halfway sums, with positive/negative signs and even/odd lower ULPs.
   Expected columns are RNE, RTZ, RDN, RUP, RMM (architectural FRM 0 through 4).
   These literal encodings do not use the protected arithmetic as an oracle. */
static const struct {
    round_encoding first;
    round_encoding second;
    round_encoding expected[5];
} sums[] = {
#ifdef ROUND_DOUBLE
    {0x3ff0000000000000ULL, 0x3ca0000000000000ULL,
     {0x3ff0000000000000ULL, 0x3ff0000000000000ULL, 0x3ff0000000000000ULL,
      0x3ff0000000000001ULL, 0x3ff0000000000001ULL}},
    {0xbff0000000000000ULL, 0xbca0000000000000ULL,
     {0xbff0000000000000ULL, 0xbff0000000000000ULL, 0xbff0000000000001ULL,
      0xbff0000000000000ULL, 0xbff0000000000001ULL}},
    {0x3ff0000000000001ULL, 0x3ca0000000000000ULL,
     {0x3ff0000000000002ULL, 0x3ff0000000000001ULL, 0x3ff0000000000001ULL,
      0x3ff0000000000002ULL, 0x3ff0000000000002ULL}},
    {0xbff0000000000001ULL, 0xbca0000000000000ULL,
     {0xbff0000000000002ULL, 0xbff0000000000001ULL, 0xbff0000000000002ULL,
      0xbff0000000000001ULL, 0xbff0000000000002ULL}}
#else
    {0x3f800000U, 0x33800000U,
     {0x3f800000U, 0x3f800000U, 0x3f800000U, 0x3f800001U, 0x3f800001U}},
    {0xbf800000U, 0xb3800000U,
     {0xbf800000U, 0xbf800000U, 0xbf800001U, 0xbf800000U, 0xbf800001U}},
    {0x3f800001U, 0x33800000U,
     {0x3f800002U, 0x3f800001U, 0x3f800001U, 0x3f800002U, 0x3f800002U}},
    {0xbf800001U, 0xb3800000U,
     {0xbf800002U, 0xbf800001U, 0xbf800002U, 0xbf800001U, 0xbf800002U}}
#endif
};

int main(void)
{
    unsigned previous_mode = round_set_mode(0);
    int result = 42;
    for (unsigned row = 0; row < sizeof(sums) / sizeof(sums[0]); ++row) {
        round_representation first = {.bits = sums[row].first};
        round_representation second = {.bits = sums[row].second};
        round_first = first.value;
        round_second = second.value;
        for (unsigned mode = 0; mode < 5; ++mode) {
            round_set_mode(mode);
            round_representation output = {.value = repair_round_bridge()};
            if (output.bits != sums[row].expected[mode] || round_get_mode() != mode) {
                result = 17;
                goto restore;
            }
        }
    }
restore:
    round_set_mode(previous_mode);
    return result;
}
