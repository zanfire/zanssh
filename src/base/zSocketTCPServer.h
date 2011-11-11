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

#ifndef ZSOCKETTCPSERVER_H__
#define ZSOCKETTCPSERVER_H__

#include "zMutex.h"
#include "zRunnable.h"
#include "zSocketTCP.h"

class zSocketTCPConnection;
class zThread;
class zSocketTCPServerListener;

class zSocketTCPServer : public zSocketTCP, public zRunnable {
protected:
  zThread* _thread;
  zMutex _mtx;
  zSocketTCPServerListener* _listener;
  bool _mustStop;
  bool _socketListening;

public:
	zSocketTCPServer(void);
	virtual ~zSocketTCPServer(void);

	void setListener(zSocketTCPServerListener* listener);

	SocketError startListen(void);
	SocketError stopListen(void);

	virtual int run(void* param);
protected:
	zSocketTCPConnection* accept(void);
};

#endif // ZSOCKETTCPSERVER_H__
