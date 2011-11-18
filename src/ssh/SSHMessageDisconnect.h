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

#ifndef SSHMESSAGEDISCONNECT_H__
#define SSHMESSAGEDISCONNECT_H__

#include "SSHMessage.h"

#include "zString.h"
#include "zVectorString.h"

/*
 * byte SSH_MSG_DISCONNECT
 * uint32 reason code
 * string description in ISO-10646 UTF-8 encoding [RFC3629]
 * string language tag [RFC3066]
 */
class SSHMessageDisconnect : public SSHMessage {
public:
  enum SSHDisconnectReasonCode {
    SSH_DISCONNECT_UNKNOWN                              = 0, // Defined by this program, must not send on the wire!
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT          = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR                       = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED                  = 3,
    SSH_DISCONNECT_RESERVED                             = 4,
    SSH_DISCONNECT_MAC_ERROR                            = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR                    = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED       = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE              = 9,
    SSH_DISCONNECT_CONNECTION_LOST                      = 10,
    SSH_DISCONNECT_BY_APPLICATION                       = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS                 = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER               = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE       = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME                    = 15
  };

public:
  SSHMessageDisconnect(unsigned char* buffer, int bufferSize);
  virtual ~SSHMessageDisconnect(void);

  //
  // Setter
  //

  // uint32 reason code
  bool setReasonCode(SSHDisconnectReasonCode code);
  // string description in ISO-10646 UTF-8 encoding [RFC3629]
  bool setDescription(zString desc);
  // string language tag [RFC3066]
  bool setLanguageTag(zString desc);

  //
  // Getter
  //

  SSHDisconnectReasonCode getReasonCode(void) const;
  // string description in ISO-10646 UTF-8 encoding [RFC3629]
  zString getDescription(void) const;
  // string language tag [RFC3066]
  zString getLanguageTag(void) const;

  zString toString(void) const;

  static char const* convSSHDisconnectReasonCodeToChars(SSHDisconnectReasonCode reason);

protected:
  virtual void impl_initPacket(void);
};

#endif // SSHMESSAGEDISCONNECT_H__
