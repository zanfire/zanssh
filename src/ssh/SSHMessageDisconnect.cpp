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

#include "SSHMessageDisconnect.h"

#include "zStringBuffer.h"
#include "zStringTokenizer.h"

#include "zRandom.h"

#include <arpa/inet.h>

SSHMessageDisconnect::SSHMessageDisconnect(unsigned char* buffer, int bufferSize) : SSHMessage(buffer, bufferSize) {
}


SSHMessageDisconnect::~SSHMessageDisconnect(void) {
}


void SSHMessageDisconnect::impl_initPacket(void) {
  SSHMessage::impl_initPacket();
  setMessageType(SSHMessage::SSH_MSG_DISCONNECT);

  /*
   * byte SSH_MSG_DISCONNECT
   * uint32 reason code
   * string description in ISO-10646 UTF-8 encoding [RFC3629]
   * string language tag [RFC3066]
   */
  char tmp[] = { 0x00, 0x00, 0x00, 0x00};
  appendPayload((unsigned char*)(&tmp), 4);
  appendPayload((unsigned char*)(&tmp), 4);
  appendPayload((unsigned char*)(&tmp), 4);
}


bool SSHMessageDisconnect::setReasonCode(SSHMessageDisconnect::SSHDisconnectReasonCode code) {
  return false;
}


bool SSHMessageDisconnect::setDescription(zString desc) {
  return false;
}


bool SSHMessageDisconnect::setLanguageTag(zString desc) {
  return false;
}


SSHMessageDisconnect::SSHDisconnectReasonCode SSHMessageDisconnect::getReasonCode(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize < 4) {
    return SSH_DISCONNECT_UNKNOWN;
  }
  if (message != NULL && messageSize >= 4) {
    uint32_t value = ntohl(((uint32_t*)message)[0]);
    if (value >= 1 && value <= 15) {
      return (SSHDisconnectReasonCode)value;
    }
  }

  return SSH_DISCONNECT_UNKNOWN;
}


zString SSHMessageDisconnect::getDescription(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize < 4) {
    return zString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(4, &message, messageSize);
  if (message != NULL && messageSize > 4) {
    return zString::fromPascalString(message, messageSize, true);
  }
  else {
    return zString();
  }
}


zString SSHMessageDisconnect::getLanguageTag(void) const {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize < 4) {
    return zString();
  }
  // Skip cookies.
  SSHMessage::skipBytes(4, &message, messageSize);
  SSHMessage::skipString(&message, messageSize);
  if (message != NULL && messageSize > 4) {
    return zString::fromPascalString(message, messageSize, true);
  }
  else {
    return zString();
  }
}


zString SSHMessageDisconnect::toString(void) const {
  zStringBuffer strb;
  strb.append(SSHPacket::toString());
  strb.appendFormatted("Reason code: [ %s ]\n", convSSHDisconnectReasonCodeToChars(getReasonCode()));
  strb.appendFormatted("Description: [ %s ]\n", getDescription().getBuffer());
  strb.appendFormatted("Encryption Algorithms Client To Server: [ %s ]\n", getLanguageTag().getBuffer());
  return strb.toString();
}


char const* SSHMessageDisconnect::convSSHDisconnectReasonCodeToChars(SSHDisconnectReasonCode reason) {
  switch (reason) {
    case SSH_DISCONNECT_UNKNOWN:                        return "SSH_DISCONNECT_UNKNOWN";
    case SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT:    return "SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT";
    case SSH_DISCONNECT_PROTOCOL_ERROR:                 return "SSH_DISCONNECT_PROTOCOL_ERROR";
    case SSH_DISCONNECT_KEY_EXCHANGE_FAILED:            return "SSH_DISCONNECT_KEY_EXCHANGE_FAILED";
    case SSH_DISCONNECT_RESERVED:                       return "SSH_DISCONNECT_RESERVED";
    case SSH_DISCONNECT_MAC_ERROR:                      return "SSH_DISCONNECT_MAC_ERROR";
    case SSH_DISCONNECT_COMPRESSION_ERROR:              return "SSH_DISCONNECT_COMPRESSION_ERROR";
    case SSH_DISCONNECT_SERVICE_NOT_AVAILABLE:          return "SSH_DISCONNECT_SERVICE_NOT_AVAILABLE";
    case SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED: return "SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED";
    case SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE:        return "SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE";
    case SSH_DISCONNECT_CONNECTION_LOST:                return "SSH_DISCONNECT_CONNECTION_LOST";
    case SSH_DISCONNECT_BY_APPLICATION:                 return "SSH_DISCONNECT_BY_APPLICATION";
    case SSH_DISCONNECT_TOO_MANY_CONNECTIONS:           return "SSH_DISCONNECT_TOO_MANY_CONNECTIONS";
    case SSH_DISCONNECT_AUTH_CANCELLED_BY_USER:         return "SSH_DISCONNECT_AUTH_CANCELLED_BY_USER";
    case SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE: return "SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE";
    case SSH_DISCONNECT_ILLEGAL_USER_NAME:              return "SSH_DISCONNECT_ILLEGAL_USER_NAME";
    default: return "???";
  }
}
