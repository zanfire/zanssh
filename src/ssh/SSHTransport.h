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
#include "zMutex.h"
#include "zThread.h"
#include "zLogger.h"
#include "zEvent.h"
#include "zVectorString.h"
#include "zSocketTCPConnection.h"
#include "zSocketTCPConnectionListener.h"
#include "KeyExchangerListener.h"


class SSHTransportListener;
class KeyExchanger;

class SSHTransport : public zRunnable, public zSocketTCPConnectionListener, public KeyExchangerListener, virtual public zObject {
public:
  enum SSHTransportDisconnectedReason {
    SSH_TRANSPORT_DISCONNECTED_REASON_UNKNOWN   = 0x00,
    SSH_TRANSPORT_DISCONNECTED_REASON_BY_REMOTE = 0x01
  };

protected:
  enum SSHTransportState {
    SSH_TRANSPORT_STATE_NONE                    = 0x00,
    SSH_TRANSPORT_STATE_VERSION_SEND            = 0x01,
    SSH_TRANSPORT_STATE_VERSION_RECEIVED        = 0x02,
    SSH_TRANSPORT_STATE_VERSION_EXCHANGED       = 0x03,
    SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND      = 0x04,
    SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED  = 0x05,
    SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED = 0x06,
    SSH_TRANSPORT_STATE_NEGO_KEY_INIT_PROGRESS  = 0x07,
    SSH_TRANSPORT_STATE_NEGO_KEY_INIT_COMPLETED = 0x08,
    SSH_TRANSPORT_STATE_DISCONNECTED            = 0xff
  };

  zMutex _mtx;
  zLogger* _logger;
  bool _mustStop;
  SSHTransportState _state;
  zThread* _thread;
  zSocketTCPConnection* _connection;
  KeyExchanger* _keyExchanger;
  zEvent _event;
  bool _listeners;
  bool _isServer;

  // Remote informations.
  zVectorString remoteKexAlgorithms;
  zVectorString remoteServerHostKeyAlgorithms;
  zVectorString remoteEncryptionAlgorithmsClientToServer;
  zVectorString remoteEncryptionAlgorithmsServerToClient;
  zVectorString remoteMacAlgorithmsClientToServer;
  zVectorString remoteMacAlgorithmsServerToClient;
  zVectorString remoteCompressionAlgorithmsClientToServer;
  zVectorString remoteCompressionAlgorithmsServerToClient;
  zVectorString remoteLanguagesClientToServer;
  zVectorString remoteLanguagesServerToClient;

public:
  SSHTransport(zSocketTCPConnection* connection, bool isServer);
  virtual ~SSHTransport(void);

  void writeMessage(unsigned char* message, int messageSize);
  void setListener(SSHTransportListener* listener);

  // zSocketTCPConnection listener impl.
  virtual void onIncomingData(unsigned char* buffer, int bufferSize);
  virtual void onDisconected(void);

  // KeyExchangerListener
  virtual void onMessageGenerated(SSHMessage const& message);
  virtual void onKeyNegotiationCompleted(void);
  virtual void onKeyNegotiationFailed(void);

  // zRunnable impl.
  virtual int run(void* param);


  static char const* convSSHTransportStateToChars(SSHTransportState state);
protected:
  // Move state machine from current state to the next.
  void newState(SSHTransportState state);

  void sendVersionMessage(void);
  void sendMessageKeyInit(void);
};

#endif // SSHTRANSPORT_H__
