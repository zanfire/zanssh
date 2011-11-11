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

#ifndef ZTHREAD_H__
#define ZTHREAD_H__

#include "global.h"
#include "zObject.h"

class zRunnable;
class zThreadMain;

#if defined(_WIN32)
  #define THREAD_ID unsigned int
  #define THREAD HANDLE
#elif HAVE_PTHREAD_H
  // Get header
  #include <pthread.h>

  #define THREAD_ID unsigned int
  #define THREAD pthread_t
#endif

#include "zMutex.h"

class zThread : public zObject {
  friend class zThreadMain;

protected:
  zRunnable* _runnable;
  THREAD _thread;
  THREAD_ID _threadID;
  void* _appParam;
  zMutex _mtxRunning;

public:
  zThread(zRunnable* runnable);
  virtual ~zThread(void);

  //
  // Static methods
  //
  static void sleep(int ms);
  static void getCurrentThreadId();

  THREAD_ID getThreadID() {return _threadID; }
  void start(void* param = NULL);
  void stop(void);
  zRunnable* getRunnable() { return _runnable; }
  bool isRunning() { return _mtxRunning.isLocked(); }

  void join();
};

#endif // ZTHREAD_H__

