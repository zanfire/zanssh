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

#include "SSHMessage.h"
#include "SSHMessageKeyInit.h"
#include "SSHMessageDisconnect.h"


#include <string.h>


SSHTransport::SSHTransport(zSocketTCPConnection* connection) : zObject(), zRunnable(), zSocketTCPConnectionListener() {
  _logger = zLogger::getLogger("SSHServer");
  _mustStop = false;
  //
  _state = SSH_TRANSPORT_STATE_NONE;
  _keyNegoState = SSH_KEY_NEGO_STATE_NONE;

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

  // Check if state machine is waiting for hello message.
  if ((_state & SSH_TRANSPORT_STATE_HELLO_RECEIVED) == 0) {
    char const sshHelloMessagePrefix[] = "SSH-2.0-";
    int sshHelloMessagePrefixSize = strlen((const char*)&sshHelloMessagePrefix);
    if (bufferSize > sshHelloMessagePrefixSize) {
      if (memcmp(buffer, (void*)&sshHelloMessagePrefix, sshHelloMessagePrefixSize) == 0) {
        // Is an hello world
        _state |= SSH_TRANSPORT_STATE_HELLO_RECEIVED;
        // For logging purpose.
        zString str = zString((char*)buffer, bufferSize);
        _logger->debug("Received SSH hello message from remote host, msg: %s len: %d", str.getBuffer(), str.getLength());
        // Consume data.
        buffer += str.getLength();
        bufferSize -= str.getLength();
      }
    }
  }

  if (bufferSize > 0) {
    SSHMessage message(buffer, bufferSize);
    if (message.getMessageType() == SSHMessage::SSH_MSG_KEXINIT) {
      SSHMessageKeyInit kexinit(buffer, bufferSize);
      _keyNegoState |= SSH_KEY_NEGO_STATE_KEY_INIT_RECEIVED;

      _logger->debug("Received KEXINIT: %s", kexinit.toString().getBuffer());
    }
    else if (message.getMessageType() == SSHMessage::SSH_MSG_DISCONNECT) {
      SSHMessageDisconnect d(buffer, bufferSize);
      _logger->debug("Received disconnect message (%s)", d.toString().getBuffer());
      onDisconected();
    }
    else {
      _logger->debug("Received message type: %d %s", message.getMessageType(), message.toString().getBuffer());
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
  while(!_mustStop) {
    // First of all send hello message.
    if ((_state & SSH_TRANSPORT_STATE_HELLO_SEND) == 0) {
      sendHelloMessage();
    }
    // Second send Key init if Transport can and is needed.
    if ((_state & SSH_TRANSPORT_STATE_HELLO_SEND) != 0 && (_keyNegoState & SSH_KEY_NEGO_STATE_KEY_INIT_SEND) == 0) {
      sendMessageKeyInit();
    }

    //
    _event.wait();
  }
  return 0;
}


void SSHTransport::sendHelloMessage(void) {
  zStringBuffer strb;
  strb.append("SSH-2.0-");
  strb.append(PACKAGE_NAME);
  strb.append('_');
  strb.append(PACKAGE_VERSION);
  strb.append("\r\n");

  zString hello = strb.toString();
  int writeBytes = _connection->writeBytes((unsigned char*)hello.getBuffer(), hello.getLength());

  if (writeBytes == (hello.getLength())) {
    _state |= SSH_TRANSPORT_STATE_HELLO_SEND;
    _logger->debug("Send hello message [%s]", hello.getBuffer());
  }
  else {
    _logger->debug("Failed send hello message %s, send return value %d.", hello.getBuffer(), writeBytes);
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
    _state |= SSH_KEY_NEGO_STATE_KEY_INIT_SEND;
  }
}
