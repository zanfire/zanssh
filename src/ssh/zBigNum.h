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

#ifndef ZBIGNUM_H__
#define ZBIGNUM_H__

#include "global.h"
#include "zObject.h"
#include "zString.h"


/**
 */
class zBigNum : zObject {
protected:
  void* _bignum;

public:
  zBigNum(void);
  zBigNum(void const* bignum);
  virtual ~zBigNum(void);

  zBigNum(const zBigNum& obj);
  zBigNum& operator=(const zBigNum& rhs);

  static zBigNum rand(int bits);
  static zBigNum pseudoRand(int bits);
  static zBigNum randRange(zBigNum const& range);
  static zBigNum pseudoRandRange(zBigNum const& range);

  static zBigNum generatePrime(int bits, bool safe, zBigNum const* zadd, zBigNum const* zrem);
  static bool isPrime(zBigNum const& bignum, int nchecks);

  zBigNum add(zBigNum b);
  zBigNum sub(zBigNum b);
  zBigNum mul(zBigNum b);
  zBigNum sqr(void);
  zBigNum div(zBigNum b);
  zBigNum mod(zBigNum b);
  zBigNum exp(zBigNum b);

  void parseFromMPInt(unsigned char* buf, int len);
  int serializeToMPInt(unsigned char* buf);

  //
  // Getters
  //
  bool isNegative(void) const;
  int getNumBits(void) const;
  int getBitAt(int idx) const;

  int compare(zBigNum const& a) const;

  virtual zString toString(void) const;

protected:
};

#endif // SSHPACKET_H_
