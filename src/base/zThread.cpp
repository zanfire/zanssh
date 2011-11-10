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

#include "zThread.h"
#include "zRunnable.h"

#if defined(_WIN32)
  #include <windows.h>
  #include <Process.h>
#else
  //#include <time.h>
#endif

#include <time.h>
#include <pthread.h>


class zThreadMain {
public:
  zThreadMain(void) {}
  ~zThreadMain(void) {}

  int main(zThread* th) {
    th->_mtxRunning.lock();
    int result = th->_runnable->run(th->_appParam);
    th->_mtxRunning.unlock();
    return result;
  }
};

namespace Protected  {

#if defined(_WIN32)
  unsigned __stdcall ThreadEntry(void* arg) {
    ThreadMain th();
    int result = th.entry(((Thread*)arg);
    _endthreadex( 0 );
    return 0;
  }
#else
  void* ThreadEntry(void* arg) {
    zThreadMain th;
    int result = th.main((zThread*)arg);
    return (void*)result;
  }
#endif
}


zThread::zThread(zRunnable* runnable) : zObject() {
  _runnable = runnable;
  //_thread = NULL;
  // No good use something like INVALID_THREAD
  _threadID = 0;
}


zThread::~zThread(void) {
  stop();
}


void zThread::sleep(int ms) {
  timespec rentime;
  timespec reqtime;

  reqtime.tv_sec = (int)(ms / 1000);
  reqtime.tv_nsec = (int)(ms % 1000) * 1000;

  int success = nanosleep(&reqtime, &rentime);
  if (success == 0) {
    // Ok
  }
  else {
    // rentime contains the remaining time that sleep has not consumed.
  }

}


void zThread::getCurrentThreadId(void) {
}


void zThread::start(void* param) {
  _appParam = param;
#if defined(_WIN32)
  //_thread = _beginthreadex( NULL, 0, &(Protected::ThreadEntry), _runnable, 0, &_threadID );
#else
  int result = pthread_create(&_thread, NULL, &(Protected::ThreadEntry), this);
  if (result == 0) {
    // thread creation success.
  }
  else {
    // thread creation failed.
  }
#endif
}


void zThread::stop(void) {

  _mtxRunning.sync();
}


void zThread::join() {
  int success = pthread_join(_thread, NULL);
  if (success == 0) {
    // ok
  }
  else {
    // ERROR
  }
}
