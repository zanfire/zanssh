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

#ifndef ZMUTEX_H__
#define ZMUTEX_H__

#include "global.h"

#if defined(_WIN32)
  #define MUTEX_TYPE void*
#elif HAVE_PTHREAD_H
  #include <pthread.h>

  #define MUTEX_TYPE pthread_mutex_t
#endif

class zMutex {
  
private:
  int _lockedCount;
  MUTEX_TYPE _mutex;
  bool _isDestroying;

public:
  zMutex(void);
  virtual ~zMutex(void);

  void lock(void);
  void unlock(void);

  void sync(void) { lock(); unlock(); }

  // Get the implementation object used by Mutex object.
  // NOTE: Return a pointer to an object valid only for the life of Mutex object.
  // NOTE: System specific method.
  MUTEX_TYPE* getImplementationMutex(void) { return &_mutex; }

  bool isLocked(void) const;
};

#endif // ZMUTEX_H__
