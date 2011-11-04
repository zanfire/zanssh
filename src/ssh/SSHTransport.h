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

#ifndef SSHTRANSPORT_H__
#define SSHTRANSPORT_H__

#include "global.h"
#include "zObject.h"
#include "zRunnable.h"
#include "zThread.h"
#include "zLogger.h"
#include "zSocketTCPConnection.h"

class SSHTransport : public zRunnable, public zObject {
protected:
  enum SSHTransportState {
    SSH_TRANSPORT_STATE_UNKNOWN         = 0x00,
    SSH_TRANSPORT_STATE_HELLO_SEND      = 0x01,
    SSH_TRANSPORT_STATE_HELLO_RECEIVED  = 0x02,
  };

  zLogger* _logger;
  int _state;
  zThread* _readThread;
  zSocketTCPConnection* _connection;
  bool _initialized;


public:
  SSHTransport(zSocketTCPConnection* connection);
  virtual ~SSHTransport(void);

  void initialize(void);

  virtual int run(void* param);

protected:
  void onIncomingData(unsigned char* buffer, int bufferSize);

  void sendHelloMessage(void);
};

#endif // SSHTransport_H__
