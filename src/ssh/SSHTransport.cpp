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

#include "SSHTransport.h"

#include "zStringBuffer.h"
#include "zVectorString.h"
#include "zScopeMutex.h"

#include "SSHMessage.h"
#include "SSHMessageKeyInit.h"
#include "SSHMessageDisconnect.h"

#include "KeyExchangerDH.h"


#include <string.h>


SSHTransport::SSHTransport(zSocketTCPConnection* connection, bool isServer) : zObject(), zRunnable(), zSocketTCPConnectionListener(), KeyExchangerListener() {
  _logger = zLogger::getLogger("SSHServer");
  _isServer = isServer;
  _keyExchanger = NULL;
  _mustStop = false;
  //
  _state = SSH_TRANSPORT_STATE_NONE;

  _connection = connection;
  _connection->acquireReference();
  _connection->setListener(this);

  _thread = new zThread(this);
  _thread->start(NULL);
}


SSHTransport::~SSHTransport() {
  _connection->releaseReference();
  _mustStop = true;
  _thread->stop();
  delete _thread;
}


void SSHTransport::onIncomingData(unsigned char* buffer, int bufferSize) {
  _logger->debug("Received %d bytes from remote host.",bufferSize);
  // If transport is disconnected don't take any action for incoming data.
  if (_state == SSH_TRANSPORT_STATE_DISCONNECTED) return;

  // Check if incoming data is a version message.
  char const sshHelloMessagePrefix[] = "SSH-2.0-";
  int sshHelloMessagePrefixSize = strlen((const char*)&sshHelloMessagePrefix);
  if (bufferSize > sshHelloMessagePrefixSize) {
    if (memcmp(buffer, (void*)&sshHelloMessagePrefix, sshHelloMessagePrefixSize) == 0) {
      // Is an hello world
      newState(SSH_TRANSPORT_STATE_VERSION_RECEIVED);
      // For logging purpose.
      zString str = zString((char*)buffer, bufferSize);
      _logger->debug("Received SSH Version message from remote host. %s ", str.substrig(0, str.getLength() - 2).getBuffer());
      // Consume data.
      buffer += str.getLength();
      bufferSize -= str.getLength();
    }
  }

  // Handle message
  if (bufferSize > 0) {
    SSHMessage message(buffer, bufferSize);

    // Check if message is valid.
    if (!message.isValid()) {
      _logger->warn("Received SSH  that is not valid.");
      // TODO: Should send a disconnect message, should made this check locally to know the exact reason etc.
    }

    if (message.getMessageType() == SSHMessage::SSH_MSG_KEXINIT) {
      SSHMessageKeyInit kexinit(buffer, bufferSize);
      newState(SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED);

      // Copy needed information for the key negotiation.
      remoteKexAlgorithms = kexinit.getKexAlgorithms();
      remoteServerHostKeyAlgorithms = kexinit.getServerHostKeyAlgorithms();
      remoteEncryptionAlgorithmsClientToServer = kexinit.getEncryptionAlgorithmsClientToServer();
      remoteEncryptionAlgorithmsServerToClient = kexinit.getEncryptionAlgorithmsServerToClient();
      remoteMacAlgorithmsClientToServer = kexinit.getMacAlgorithmsClientToServer();
      remoteMacAlgorithmsServerToClient = kexinit.getMacAlgorithmsServerToClient();
      remoteCompressionAlgorithmsClientToServer = kexinit.getCompressionAlgorithmsClientToServer();
      remoteCompressionAlgorithmsServerToClient = kexinit.getCompressionAlgorithmsServerToClient();
      remoteLanguagesClientToServer = kexinit.getLanguagesClientToServer();
      remoteLanguagesServerToClient = kexinit.getLanguagesServerToClient();

      _logger->debug("Received KEXINIT: %s", kexinit.toString().getBuffer());
    }
    else if (message.getMessageType() >= SSHMessage::SSH_MSG_KEX_30 && message.getMessageType() <= SSHMessage::SSH_MSG_KEX_30) {
      // Handle key negotiation message to the key exchanger.
      if (_keyExchanger != NULL) {
        _keyExchanger->onReceivedSSHMessage(message);
      }
    }
    else if (message.getMessageType() == SSHMessage::SSH_MSG_DISCONNECT) {
      newState(SSH_TRANSPORT_STATE_DISCONNECTED);
      SSHMessageDisconnect d(buffer, bufferSize);
      _logger->debug("Received disconnect message %s", d.toString().getBuffer());
      onDisconected();
    }
    else {
      _logger->debug("Received unknown message type: %d", message.getMessageType());
    }
  }

  _event.signal();
}


void SSHTransport::onDisconected(void) {
  _mustStop = true;
  _event.signal();
  _thread->stop();
}


int SSHTransport::run(void* param) {
  //
  // State machine.
  //

  while(!_mustStop) {
    _mtx.lock();
    if (_state == SSH_TRANSPORT_STATE_NONE || _state == SSH_TRANSPORT_STATE_VERSION_RECEIVED) {
      sendVersionMessage();
    }
    if (_state == SSH_TRANSPORT_STATE_VERSION_EXCHANGED || _state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED) {
      sendMessageKeyInit();
    }
    if (_state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED) {
      // Evaluate what key exchanger should be instantiated.
      _keyExchanger = new KeyExchangerDH();
      _keyExchanger->setListener(this);
    }
    _mtx.unlock();
    //
    _event.wait();
  }
  return 0;
}


void SSHTransport::newState(SSHTransport::SSHTransportState state) {
  zScopeMutex scope(_mtx);

  _logger->debug("Requested to update state from %s to %s.", convSSHTransportStateToChars(_state), convSSHTransportStateToChars(state));

  if (_state == state) return;

  if (state == SSH_TRANSPORT_STATE_NONE) return;
  if (_state == SSH_TRANSPORT_STATE_DISCONNECTED) return;

  if (state == SSH_TRANSPORT_STATE_VERSION_SEND) {
    if (_state == SSH_TRANSPORT_STATE_VERSION_RECEIVED) _state = SSH_TRANSPORT_STATE_VERSION_EXCHANGED;
    if (_state == SSH_TRANSPORT_STATE_NONE) _state = SSH_TRANSPORT_STATE_VERSION_SEND;
  }
  else if (state == SSH_TRANSPORT_STATE_VERSION_RECEIVED) {
    if (_state == SSH_TRANSPORT_STATE_VERSION_SEND) _state = SSH_TRANSPORT_STATE_VERSION_EXCHANGED;
    if (_state == SSH_TRANSPORT_STATE_NONE) _state = SSH_TRANSPORT_STATE_VERSION_RECEIVED;
  }
  else if (state == SSH_TRANSPORT_STATE_VERSION_EXCHANGED) {
    // NOPE? Is not allowed to inject exchanged state from external invocation.
  }
  else if (state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND) {
    if (_state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED) _state = SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED;
    if (_state == SSH_TRANSPORT_STATE_VERSION_EXCHANGED) _state = SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND;
  }
  else if (state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED) {
    if (_state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND) _state = SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED;
    // Allowed to go back to this state at first time (VERSION_EXCHANGED) and after key negotiation.
    if (_state >= SSH_TRANSPORT_STATE_VERSION_EXCHANGED && _state != SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED) _state = SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED;
  }
  else if (state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED) {
    // NOPE? Is not allowed to inject exchanged state from external invocation.
  }
  else if (state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_PROGRESS) {
    // TODO: todo
  }
  else if (state == SSH_TRANSPORT_STATE_NEGO_KEY_INIT_COMPLETED) {
    // TODO: todo
  }
  else if (state == SSH_TRANSPORT_STATE_DISCONNECTED) {
    _state = state;
  }

  _event.signal();
}


void SSHTransport::sendVersionMessage(void) {
  zStringBuffer strb;
  strb.append("SSH-2.0-");
  strb.append(PACKAGE_NAME);
  strb.append('_');
  strb.append(PACKAGE_VERSION);
  strb.append("\r\n");

  zString version = strb.toString();
  int writeBytes = _connection->writeBytes((unsigned char*)version.getBuffer(), version.getLength());

  if (writeBytes == version.getLength()) {
    newState(SSH_TRANSPORT_STATE_VERSION_SEND);
    _logger->debug("Send Version message [%s]", version.substrig(0, version.getLength() - 2).getBuffer());
  }
  else {
    _logger->debug("Failed send hello message %s, send return value %d.", version.getBuffer(), writeBytes);
  }
}


void SSHTransport::sendMessageKeyInit(void) {
  unsigned char buffer[1024 * 64];
  SSHMessageKeyInit msg(buffer, sizeof(buffer));
  msg.initPacket();

  zVectorString empty(false, 12);
  zVectorString none(false, 12);
  none.append(zString("none"));

  zVectorString kex(false, 12);
  kex.append(zString("diffie-hellman-group1-sha1"));
  kex.append(zString("diffie-hellman-group14-sha1"));
  msg.setKexAlgorithms(kex);

  zVectorString hostkey(false, 12);
  hostkey.append(zString("ssh-dss"));
  hostkey.append(zString("ssh-rsa"));
  msg.setServerHostKeyAlgorithms(hostkey);

  zVectorString enc(false, 12);
  enc.append(zString("3des-cbc"));
  enc.append(zString("aes128-cbc"));
  msg.setEncryptionAlgorithmsClientToServer(enc);
  msg.setEncryptionAlgorithmsServerToClient(enc);

  zVectorString mac(false, 12);
  mac.append(zString("hmac-sha1"));
  mac.append(zString("hmac-sha1-96"));
  msg.setMacAlgorithmsClientToServer(mac);
  msg.setMacAlgorithmsServerToClient(mac);

  msg.setCompressionAlgorithmsClientToServer(none);
  msg.setCompressionAlgorithmsServerToClient(none);

  msg.setLanguagesClientToServer(empty);
  msg.setLanguagesServerToClient(empty);
  msg.setFirstKexPacketFollows(false);
  msg.setReserved(0);

  msg.finalize();

  _logger->debug("Prepared KEXINIT: %s", msg.toString().getBuffer());
  int writeBytes = _connection->writeBytes(msg.getBuffer(), msg.getBufferContentSize());

  if (writeBytes == msg.getBufferContentSize()) {
    newState(SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND);
  }
}


void SSHTransport::onMessageGenerated(SSHMessage const& message) {

}


void SSHTransport::onKeyNegotiationCompleted(void) {

}


void SSHTransport::onKeyNegotiationFailed(void) {

}


char const* SSHTransport::convSSHTransportStateToChars(SSHTransportState state) {
  switch(state) {
    case SSH_TRANSPORT_STATE_NONE:                    return "SSH_TRANSPORT_STATE_NONE";
    case SSH_TRANSPORT_STATE_VERSION_SEND:            return "SSH_TRANSPORT_STATE_VERSION_SEND";
    case SSH_TRANSPORT_STATE_VERSION_RECEIVED:        return "SSH_TRANSPORT_STATE_VERSION_RECEIVED";
    case SSH_TRANSPORT_STATE_VERSION_EXCHANGED:       return "SSH_TRANSPORT_STATE_VERSION_EXCHANGED";
    case SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND:      return "SSH_TRANSPORT_STATE_NEGO_KEY_INIT_SEND";
    case SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED:  return "SSH_TRANSPORT_STATE_NEGO_KEY_INIT_RECEIVED";
    case SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED: return "SSH_TRANSPORT_STATE_NEGO_KEY_INIT_EXCHANGED";
    case SSH_TRANSPORT_STATE_NEGO_KEY_INIT_PROGRESS:  return "SSH_TRANSPORT_STATE_NEGO_KEY_INIT_PROGRESS";
    case SSH_TRANSPORT_STATE_NEGO_KEY_INIT_COMPLETED: return "SSH_TRANSPORT_STATE_NEGO_KEY_INIT_COMPLETED";
    case SSH_TRANSPORT_STATE_DISCONNECTED:            return "SSH_TRANSPORT_STATE_DISCONNECTED";
  }

  return "??";
}
