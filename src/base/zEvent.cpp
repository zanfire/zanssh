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


#include "zEvent.h"

#include "zLogger.h"

zEvent::zEvent(void) {
#if defined(_WIN32)
  _event = INVALID_HANDLE;
  _event = CreateEvent(NULL, true, false, NULL);
#elif HAVE_PTHREAD_H
  int res = pthread_cond_init(&_event, NULL);
  CHECK_FATAL(res, "pthread_cond_init");
#endif
}


zEvent::~zEvent(void) {
#if defined(_WIN32)
  if(_event != NULL) {
    CloseHandle(_event);
    _event = NULL;
  }
#elif HAVE_PTHREAD_H
  int success = pthread_cond_destroy(&_event);
    if (success == 0) {
      // Ok
    }
    else {
      // Error
    }
#endif
}


void zEvent::wait(int timeoutMillis) {
#if defined(_WIN32)
  DWORD res = WaitForSingleObject( _event, timeoutMillis);
#elif HAVE_PTHREAD_H
  _mtx.lock();
  int success = -1;
  if (timeoutMillis < 0) {
    success = pthread_cond_wait(&_event, _mtx.getImplementationMutex());
  }
  else {
    timespec request_time;

    request_time.tv_sec = (int)(timeoutMillis / 1000);
    request_time.tv_nsec = (int)(timeoutMillis % 1000) * 1000;
    success = pthread_cond_timedwait(&_event, _mtx.getImplementationMutex(), &request_time);
  }

  if (success == 0) {
    // Ok
  }
  else {
    // Error
  }
  _mtx.unlock();
#endif
}


void zEvent::signal(void) {
#if defined(_WIN32)
  SetEvent( _event );
#elif HAVE_PTHREAD_H
  int success = pthread_cond_signal(&_event);
    if (success == 0) {
      // Ok
    }
    else {
      // Error
    }
#endif
}

