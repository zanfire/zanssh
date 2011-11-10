/******************************************************************************
 * Copyright 2011 Matteo Valdina
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

#ifndef SOCKETTCPCONNECTION_H__
#define SOCKETTCPCONNECTION_H__

#include "global.h"
#include "zObject.h"
#include "zRunnable.h"
#include "zMutex.h"
#include "zSocketTCP.h"
#include "zSocketTCPConnectionListener.h"


class zSocketAddress;
class zThread;
class zSocketTCP;

class zSocketTCPConnection : public zRunnable, virtual public zObject {
protected:
  zSocketTCP* _socket;
  zSocketAddress* _remoteAddr;
  int _remotePort;
  bool _mustStop;
  //
  zMutex _mtx;
  zThread* _thread;
  zSocketTCPConnectionListener* _listener;

public:
  zSocketTCPConnection(zSocketTCP* socket, zSocketAddress* remoteAddr);
  virtual ~zSocketTCPConnection(void);

  void setListener(zSocketTCPConnectionListener* listener);
  int writeBytes(unsigned char* buffer, int bufferSize);

protected:
  // zRunnable implementation
  int run(void* param);
  void stop(void);

  int readBytes(unsigned char* buffer, int bufferSize);
};

#endif // SOCKETTCPCONNECTION_H__
