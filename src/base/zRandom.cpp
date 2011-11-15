/******************************************************************************
 * Copyright 2009 Matteo Valdina
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

#include "zRandom.h"

#include "zMutex.h"
#include "zLogger.h"

#include <sys/time.h>


zMutex* zRandom::_singletonMtx = new zMutex();
zRandom* zRandom::_singleton = NULL;


zRandom* zRandom::getSingleton(void) {
  _singletonMtx->lock();
  if (_singleton == NULL) _singleton = new zRandom();
  _singletonMtx->unlock();
  return _singleton;
}

zRandom::zRandom(void) {
  struct timeval t;
  gettimeofday(&t, NULL);

  int ret = initstate_r(t.tv_sec, (char*)(&_randstate), sizeof(_randstate), &_randdata);
  CHECK_FATAL(ret, "initstate_r");
}


zRandom::~zRandom(void) {
  // nop
}


int zRandom::nextInt(void) {
  int32_t result;
  int ret = random_r(&_randdata, &result);
  if (ret == -1) {
    CHECK_FATAL(errno, "random_r");
  }
  return result;
}
