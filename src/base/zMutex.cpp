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

#include "zMutex.h"
#include "zLogger.h"

#include <stdio.h>
zMutex::zMutex(void) {
  _isDestroying = false;

#if defined(_WIN32)
	_cs = new CRITICAL_SECTION;
  InitializeMutexAndSpinCount((LPCRITICAL_SECTION)_cs, 500);
#else
  pthread_mutexattr_t mutexAttr;

  int res = pthread_mutexattr_init(&mutexAttr);
  CHECK_FATAL(res, "pthread_mutexattr_init");

  res = pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE);
  CHECK_FATAL(res, "pthread_mutexattr_settype PTHREAD_MUTEX_RECURSIVE");

  res = pthread_mutex_init(&_mutex, &mutexAttr);
  CHECK_FATAL(res, "pthread_mutex_init");

  res = pthread_mutexattr_destroy(&mutexAttr);
  CHECK_FATAL(res, "pthread_mutexattr_destroy");
#endif
}


zMutex::~zMutex() {
  sync();

#if defined(_WIN32)
  DeleteMutex((LPCRITICAL_SECTION)_cs);
	delete (CRITICAL_SECTION*)_cs;
#else
	int res = pthread_mutex_destroy(&_mutex);
	CHECK_FATAL(res, "pthread_mutex_destroy");
#endif
}


void zMutex::lock() {
#if defined(_WIN32)
  EnterMutex((LPCRITICAL_SECTION)_cs);
#else
  int res = pthread_mutex_lock(&_mutex);
  CHECK_FATAL(res, "pthread_mutex_lock");
#endif

}


void zMutex::unlock() {
#if defined(_WIN32)
  LeaveMutex((LPCRITICAL_SECTION)_cs);
#else
  int res = pthread_mutex_unlock(&_mutex);
  CHECK_FATAL(res, "pthread_mutex_unlock");
#endif
}
