#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <stdint.h>

#define FP_SHIFT_AMOUNT 14
#define FP_SCALE (1 << FP_SHIFT_AMOUNT)

#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

/* Integer <-> Fixed-Point */
static inline int int_to_fp(int n) {
  return n * FP_SCALE;
}

static inline int fp_to_int(int x) {
  return x / FP_SCALE;
}

static inline int fp_to_int_round(int x) {
  if (x >= 0)
    return (x + FP_SCALE / 2) / FP_SCALE;
  else
    return (x - FP_SCALE / 2) / FP_SCALE;
}

/* Fixed-Point <-> Fixed-Point */
static inline int add_fp(int x, int y) {
  return x + y;
}

static inline int sub_fp(int x, int y) {
  return x - y;
}

static inline int mult_fp(int x, int y) {
  return ((int64_t)x) * y / FP_SCALE;
}

static inline int div_fp(int x, int y) {
  return ((int64_t)x) * FP_SCALE / y;
}

/* Fixed-Point <-> Integer */
static inline int add_mixed(int x, int n) {
  return x + n * FP_SCALE;
}

static inline int sub_mixed(int x, int n) {
  return x - n * FP_SCALE;
}

static inline int mult_mixed(int x, int n) {
  return x * n;
}

static inline int div_mixed(int x, int n) {
  return x / n;
}

#endif /* FIXED_POINT_H */


