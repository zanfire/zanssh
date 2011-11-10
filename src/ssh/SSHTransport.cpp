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
#include "SSHMessage.h"
#include "SSHMessageKeyInit.h"

#include <string.h>


SSHTransport::SSHTransport(zSocketTCPConnection* connection) : zObject(), zRunnable() {
  _logger = zLogger::getLogger("SSHServer");
  _initialized = false;

  //
  _state = SSH_TRANSPORT_STATE_UNKNOWN;
  _keyNegoState = SSH_KEY_NEGO_STATE_UNKNOWN;

  _connection = connection;
  _connection->acquireReference();

  _readThread = new zThread(this);
}


SSHTransport::~SSHTransport() {
  _connection->releaseReference();

}


void SSHTransport::initialize(void) {
  if (_initialized) {
    _logger->error("Initialization skipped, SSHTRansport is just initialized.");
    return;
  }

  _state = SSH_TRANSPORT_STATE_UNKNOWN;
  _initialized = true;
  _readThread->start(NULL);
  sendHelloMessage();

  _logger->debug("SSHTransport is initialized correctly.");
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
      SSHMessageKeyInit keyInit(buffer, bufferSize);
      _keyNegoState |= SSH_KEY_NEGO_STATE_KEY_INIT_RECEIVED;
    }
    //else if (message.getMessageType() == SSHMessage:SSH_MS) {
  }
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
  SSHMessageKeyInit key(buffer, sizeof(buffer));

  key.initPacket();

}
