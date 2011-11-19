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


void SSHMessage::impl_initPacket(void) {
  SSHPacket::impl_initPacket();
  char tmp[] = { 0x00 };
  appendPayload((unsigned char*)&tmp, 1);
}


bool SSHMessage::setMessageType(SSHMessage::SSHMessageType type) {
  int payloadSize = 0;
  unsigned char* payload = getPayload(payloadSize);
  if (payload == NULL) return false;
  if (payloadSize == 0) return false;

  payload[0] = type;
  return true;
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


zString SSHMessage::toString(void) const {
  zStringBuffer strb;
  strb.append(SSHPacket::toString());
  strb.append("\nMessage type: ");
  strb.append(convSSHMessageTypeToChars(getMessageType()));
  return strb.toString();
}


int SSHMessage::skipBytes(int bytes, unsigned char** message, int& messageSize) {
  if (message == NULL) return 0; // Nothing to do.
  if (*message == NULL) return 0; // Nothing to do.
  if (messageSize < bytes) {
    *message = NULL;
    messageSize = 0;
    return 0;
  }

  *message = *message + bytes;
  messageSize -= bytes;
  return bytes;
}


int SSHMessage::skipString(unsigned char** message, int& messageSize) {
  if (message == NULL) return 0; // Nothing to do.
  if (*message == NULL) return 0; // Nothing to do.
  if (messageSize < 4) return 0; // Nothing to do.
  // Read length of name list.
  uint32_t length = ntohl(((uint32_t*)*message)[0]);
  return skipBytes(length + 4, message, messageSize);

}


char const* SSHMessage::convSSHMessageTypeToChars(SSHMessageType type) {
  switch(type) {
    case SSH_MSG_INVALID:                     return "SSH_MSG_INVALID";
    case SSH_MSG_DISCONNECT:                  return "SSH_MSG_DISCONNECT";
    case SSH_MSG_IGNORE:                      return "SSH_MSG_IGNORE";
    case SSH_MSG_UNIMPLEMENTED:               return "SSH_MSG_UNIMPLEMENTED";
    case SSH_MSG_DEBUG:                       return "SSH_MSG_DEBUG";
    case SSH_MSG_SERVICE_REQUEST:             return "SSH_MSG_SERVICE_REQUEST";
    case SSH_MSG_SERVICE_ACCEPT:              return "SSH_MSG_SERVICE_ACCEPT";
    case SSH_MSG_KEXINIT:                     return "SSH_MSG_KEXINIT";
    case SSH_MSG_NEWKEYS:                     return "SSH_MSG_NEWKEYS";
    case SSH_MSG_USERAUTH_REQUEST:            return "SSH_MSG_USERAUTH_REQUEST";
    case SSH_MSG_USERAUTH_FAILURE:            return "SSH_MSG_USERAUTH_FAILURE";
    case SSH_MSG_USERAUTH_SUCCESS:            return "SSH_MSG_USERAUTH_SUCCESS";
    case SSH_MSG_USERAUTH_BANNER:             return "SSH_MSG_USERAUTH_BANNER";
    case SSH_MSG_GLOBAL_REQUEST:              return "SSH_MSG_GLOBAL_REQUEST";
    case SSH_MSG_REQUEST_SUCCESS:             return "SSH_MSG_REQUEST_SUCCESS";
    case SSH_MSG_REQUEST_FAILURE:             return "SSH_MSG_REQUEST_FAILURE";
    case SSH_MSG_CHANNEL_OPEN:                return "SSH_MSG_CHANNEL_OPEN";
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:   return "SSH_MSG_CHANNEL_OPEN_CONFIRMATION";
    case SSH_MSG_CHANNEL_OPEN_FAILURE:        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    case SSH_MSG_CHANNEL_WINDOW_ADJUST:       return "SSH_MSG_CHANNEL_WINDOW_ADJUST";
    case SSH_MSG_CHANNEL_DATA:                return "SSH_MSG_CHANNEL_DATA";
    case SSH_MSG_CHANNEL_EXTENDED_DATA:       return "SSH_MSG_CHANNEL_EXTENDED_DATA";
    case SSH_MSG_CHANNEL_EOF:                 return "SSH_MSG_CHANNEL_EOF";
    case SSH_MSG_CHANNEL_CLOSE:               return "SSH_MSG_CHANNEL_CLOSE";
    case SSH_MSG_CHANNEL_REQUEST:             return "SSH_MSG_CHANNEL_REQUEST";
    case SSH_MSG_CHANNEL_SUCCESS:             return "SSH_MSG_CHANNEL_SUCCESS";
    case SSH_MSG_CHANNEL_FAILURE:             return "SSH_MSG_CHANNEL_FAILURE";
    default: break;
  }
  return "??";
}
