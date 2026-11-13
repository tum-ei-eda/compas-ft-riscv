#ifndef COMPAS_REGRESSION_REPAIR_ROUNDING_H
#define COMPAS_REGRESSION_REPAIR_ROUNDING_H

#define NOINLINE __attribute__((noinline))
#ifdef ROUND_DOUBLE
typedef double round_value;
typedef unsigned long long round_encoding;
#else
typedef float round_value;
typedef unsigned int round_encoding;
#endif

typedef union {
    round_value value;
    round_encoding bits;
} round_representation;

extern volatile round_value round_first;
extern volatile round_value round_second;
NOINLINE round_value repair_round_add(void);
NOINLINE round_value repair_round_bridge(void);
NOINLINE unsigned round_set_mode(unsigned mode);
NOINLINE unsigned round_get_mode(void);

#endif
