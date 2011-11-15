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
#include "zEvent.h"
#include "zSocketTCPConnection.h"
#include "zSocketTCPConnectionListener.h"


class SSHTransportListener;

class SSHTransport : public zRunnable, public zSocketTCPConnectionListener, virtual public zObject {
public:
  enum SSHTransportDisconnectedReason {
    SSH_TRANSPORT_DISCONNECTED_REASON_UNKNOWN   = 0x00,
    SSH_TRANSPORT_DISCONNECTED_REASON_BY_REMOTE = 0x01
  };

protected:
  enum SSHTransportState {
    SSH_TRANSPORT_STATE_NONE         = 0x00,
    SSH_TRANSPORT_STATE_HELLO_SEND      = 0x01,
    SSH_TRANSPORT_STATE_HELLO_RECEIVED  = 0x02,
  };

  enum SSHKeyNegotiationState {
    SSH_KEY_NEGO_STATE_NONE            = 0x00,
    SSH_KEY_NEGO_STATE_KEY_INIT_SEND      = 0x01,
    SSH_KEY_NEGO_STATE_KEY_INIT_RECEIVED  = 0x02,
  };

  zMutex* _mtx;
  zLogger* _logger;
  bool _mustStop;
  int _state;
  int _keyNegoState;
  zThread* _thread;
  zSocketTCPConnection* _connection;
  zEvent _event;
  bool _listeners;


public:
  SSHTransport(zSocketTCPConnection* connection);
  virtual ~SSHTransport(void);

  void writeMessage(unsigned char* message, int messageSize);
  void setListener(SSHTransportListener* listener);

  // zSocketTCPConnection listener impl.
  virtual void onIncomingData(unsigned char* buffer, int bufferSize);
  virtual void onDisconected(void);

  // zRunnable impl.
  virtual int run(void* param);

protected:

  void sendHelloMessage(void);
  void sendMessageKeyInit(void);
};

#endif // SSHTRANSPORT_H__
