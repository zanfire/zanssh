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

#ifndef ZRANDOM_H__
#define ZRANDOM_H__

#include "global.h"

#include <stdlib.h>

class zMutex;

class zRandom {
private:
  static zMutex* _singletonMtx;
  static zRandom* _singleton;

  char _randstate[256];
  random_data _randdata;

public:
  static zRandom* getSingleton(void);
  // Anyway can create independent instances.
  zRandom(void);
  ~zRandom(void);

  uint8_t nextByte(void);
  int nextInt(void);

private:
};

#endif // ZRANDOM_H__
