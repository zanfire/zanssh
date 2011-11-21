/******************************************************************************
 * Copyright 2009-2011 Matteo Valdina
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *****************************************************************************/


#include "zBigNum.h"

#include "zStringBuffer.h"
#include <openssl/bn.h>


zBigNum::zBigNum(void) : zObject() {
  _bignum = BN_new();
  BN_init((BIGNUM*)_bignum);
  BN_zero((BIGNUM*)_bignum);
}


zBigNum::zBigNum(void const* bignum) : zObject() {
  _bignum = BN_new();
   BN_init((BIGNUM*)_bignum);
   _bignum = BN_dup((BIGNUM*)bignum);
}


zBigNum::~zBigNum(void) {
  BN_clear_free((BIGNUM*)_bignum);
  _bignum = NULL;
}


zBigNum::zBigNum(const zBigNum& bignum) : zObject() {
  _bignum = BN_dup((BIGNUM*)bignum._bignum);
}


zBigNum& zBigNum::operator=(const zBigNum& bignum) {
  if (this != &bignum) {
    BN_clear_free((BIGNUM*)_bignum);
    _bignum = BN_dup((BIGNUM*)bignum._bignum);
  }

  return *this;
}


void zBigNum::parseFromMPInt(unsigned char* buf, int len) {
  //int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
  BIGNUM* res = BN_mpi2bn(buf, len, (BIGNUM*)_bignum);
  if (res != NULL) {
    BN_free(res);
  }
}


int zBigNum::serializeToMPInt(unsigned char* buf) {
  //int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
  return BN_bn2mpi((BIGNUM*)_bignum, buf);
}


zBigNum zBigNum::add(zBigNum b) {
  zBigNum r;
  if (BN_add((BIGNUM*)r._bignum, (BIGNUM*)_bignum, (BIGNUM*)b._bignum) == 1) {
    return r;
  }
  return r;
}

zBigNum zBigNum::sub(zBigNum b) {
  zBigNum r;
  if (BN_sub((BIGNUM*)r._bignum, (BIGNUM*)_bignum, (BIGNUM*)b._bignum) == 1) {
    return r;
  }
  return r;
}


zBigNum zBigNum::mul(zBigNum b) {
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  zBigNum r;
  BN_mul((BIGNUM*)r._bignum, (BIGNUM*)_bignum, (BIGNUM*)b._bignum, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return r;
}


zBigNum zBigNum::sqr(void) {
  //int (BIGNUM *r, BIGNUM *a, BN_CTX *ctx);
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  zBigNum r;
  BN_sqr((BIGNUM*)r._bignum, (BIGNUM*)_bignum, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return r;
}


zBigNum zBigNum::div(zBigNum b) {
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  zBigNum r;
  BN_div((BIGNUM*)r._bignum, NULL, (BIGNUM*)_bignum, (BIGNUM*)b._bignum, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return r;
}


zBigNum zBigNum::mod(zBigNum b) {
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  zBigNum r;
  BN_mod((BIGNUM*)r._bignum, (BIGNUM*)_bignum, (BIGNUM*)b._bignum, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return r;
}


zBigNum zBigNum::exp(zBigNum b) {
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  zBigNum r;
  BN_exp((BIGNUM*)r._bignum, (BIGNUM*)_bignum, (BIGNUM*)b._bignum, ctx);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return r;
}


//int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
zBigNum zBigNum::rand(int bits) {
  zBigNum rnd;
  if (BN_rand((BIGNUM*)rnd._bignum, bits, 0, 0) == 1) {
    return rnd;
  }
  return rnd;
}


//int (BIGNUM *rnd, int bits, int top, int bottom);
zBigNum zBigNum::pseudoRand(int bits) {
  zBigNum rnd;
  if (BN_pseudo_rand((BIGNUM*)rnd._bignum, bits, 0, 0) == 1) {
    return rnd;
  }
  return rnd;
}


zBigNum zBigNum::randRange(zBigNum const& range) {
  zBigNum rnd;
  if (BN_rand_range((BIGNUM*)rnd._bignum, (BIGNUM*)range._bignum) == 1) {
    return rnd;
  }
  return rnd;
}



zBigNum zBigNum::pseudoRandRange(zBigNum const& range) {
  zBigNum rnd;
  if (BN_pseudo_rand_range((BIGNUM*)rnd._bignum, (BIGNUM*)range._bignum) == 1) {
    return rnd;
  }
  return rnd;
}


zBigNum zBigNum::generatePrime(int bits, bool safe, zBigNum const* zadd, zBigNum const* zrem) {

  /*
   * BN_generate_prime() generates a pseudo-random prime number of num bits.  If ret is not NULL, it will be used to store the number.
   * If callback is not NULL, it is called as follows:
   *   o   callback(0, i, cb_arg) is called after generating the i-th potential prime number.
   *   o   While the number is being tested for primality, callback(1, j, cb_arg) is called as described below.
   *   o   When a prime has been found, callback(2, i, cb_arg) is called.
   * The prime may have to fulfill additional requirements for use in Diffie-Hellman key exchange:
   * If add is not NULL, the prime will fulfill the condition p % add == rem (p % add == 1 if rem == NULL) in order to suit a given generator.
   * If safe is true, it will be a safe prime (i.e. a prime p so that (p-1)/2 is also prime).
   *
   *
   * TODO: The PRNG must be seeded prior to calling BN_generate_prime().  The prime number generation has a negligible error probability.
   */

  zBigNum pri;
  BIGNUM* add = zadd != NULL ? (BIGNUM*)zadd->_bignum : NULL;
  BIGNUM* rem = zrem != NULL ? (BIGNUM*)zrem->_bignum : NULL;
  BN_generate_prime((BIGNUM*)pri._bignum, bits, safe, add, rem, NULL, NULL);
  return pri;
}


bool zBigNum::isPrime(zBigNum const& bignum, int nchecks) {
  /*
   * BN_is_prime() and BN_is_prime_fasttest() test if the number a is prime.  The following tests are performed until one of them shows that a is composite; if a passes
   * all these tests, it is considered prime.
   * BN_is_prime_fasttest(), when called with do_trial_division == 1, first attempts trial division by a number of small primes; if no divisors are found by this test and
   * callback is not NULL, callback(1, -1, cb_arg) is called.  If do_trial_division == 0, this test is skipped.
   * Both BN_is_prime() and BN_is_prime_fasttest() perform a Miller-Rabin probabilistic primality test with checks iterations. If checks == BN_prime_checks, a number of
   * iterations is used that yields a false positive rate of at most 2^-80 for random input.
   * If callback is not NULL, callback(1, j, cb_arg) is called after the j-th iteration (j = 0, 1, ...). ctx is a pre-allocated BN_CTX (to save the overhead of allocating
   * and freeing the structure in a loop), or NULL.
   */
  BN_CTX* ctx = BN_CTX_new();
  BN_CTX_init(ctx);
  int ret = BN_is_prime((BIGNUM*)bignum._bignum, nchecks, NULL, ctx, NULL);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);

  return (ret == 1); // returns 0 if the number is composite, 1 if it is prime with an error probability of less than 0.25^checks, and -1 on error.
}


bool zBigNum::isNegative(void) const {
  return BN_is_negative((BIGNUM*)_bignum);
}


int zBigNum::getNumBits(void) const {
  return BN_num_bits((BIGNUM*)_bignum);
}


int zBigNum::getBitAt(int idx) const {
  return BN_is_bit_set((BIGNUM*)_bignum, idx);
}


int zBigNum::compare(zBigNum const& a) const {
  return BN_cmp((BIGNUM*)_bignum, (BIGNUM*)a._bignum);
}


zString zBigNum::toString(void) const {
  zStringBuffer strb;
  return strb.toString();
}
