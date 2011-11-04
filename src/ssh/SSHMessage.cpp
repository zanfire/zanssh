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

#include "SSHMessage.h"

#include "zStringBuffer.h"

#include <arpa/inet.h>



SSHMessage::SSHMessage(unsigned char* buffer, int bufferSize) : SSHPacket(buffer, bufferSize) {
}


SSHMessage::~SSHMessage(void) {
}


SSHMessage::SSHMessageType SSHMessage::getMessageType(void) const {
  int payloadSize = 0;
  unsigned char* payload = getPayload(payloadSize);
  if (payload == NULL) return SSH_MSG_INVALID;

  SSHMessageType msgType = (SSHMessageType)payload[0];
  return msgType;
}


unsigned char* SSHMessage::getMessage(int& messageSize) const {
  int payloadSize = 0;

  messageSize = 0;
  unsigned char* message = NULL;
  unsigned char* payload = getPayload(payloadSize);
  if (payload != NULL && payloadSize > 1) {
    // Valid message
    messageSize = payloadSize -1;
    message = (payload +1);
  }
  return message;
}


zString SSHMessage::toString(void) {
  zStringBuffer strb;
  return strb.toString();
}


void SSHMessage::skipBytes(int bytes, unsigned char** message, int& messageSize) {
  if (message == NULL) return; // Nothing to do.
  if (*message == NULL) return; // Nothing to do.
  if (messageSize < bytes) return; // Nothing to do.

  *message = *message + bytes;
  messageSize -= bytes;
}


void SSHMessage::skipNameList(unsigned char** message, int& messageSize) {
  if (message == NULL) return; // Nothing to do.
  if (*message == NULL) return; // Nothing to do.
  if (messageSize >= 4) return; // Nothing to do.
  // Read length of name list.
  uint32_t length = ((uint32_t*)message)[0];
  skipBytes(length, message, messageSize);
}
