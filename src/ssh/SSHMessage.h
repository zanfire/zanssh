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

#ifndef SSHMESSAGE_H__
#define SSHMESSAGE_H__

#include "SSHPacket.h"

#include "zString.h"

class SSHMessage : public SSHPacket {
public:

  enum SSHMessageType {
    SSH_MSG_INVALID                     = -1, //
    SSH_MSG_DISCONNECT                  = 1,  // [SSH-TRANS]
    SSH_MSG_IGNORE                      = 2,  // [SSH-TRANS]
    SSH_MSG_UNIMPLEMENTED               = 3,  // [SSH-TRANS]
    SSH_MSG_DEBUG                       = 4,  // [SSH-TRANS]
    SSH_MSG_SERVICE_REQUEST             = 5,  // [SSH-TRANS]
    SSH_MSG_SERVICE_ACCEPT              = 6,  // [SSH-TRANS]
    SSH_MSG_KEXINIT                     = 20, // [SSH-TRANS]
    SSH_MSG_NEWKEYS                     = 21, // [SSH-TRANS]
    SSH_MSG_KEX_30                      = 30,
    SSH_MSG_KEX_31                      = 31,
    SSH_MSG_KEX_32                      = 32,
    SSH_MSG_KEX_33                      = 33,
    SSH_MSG_KEX_34                      = 34,
    SSH_MSG_KEX_35                      = 35,
    SSH_MSG_KEX_36                      = 36,
    SSH_MSG_KEX_37                      = 37,
    SSH_MSG_KEX_38                      = 38,
    SSH_MSG_KEX_39                      = 39,
    SSH_MSG_KEX_40                      = 40,
    SSH_MSG_KEX_41                      = 41,
    SSH_MSG_KEX_42                      = 42,
    SSH_MSG_KEX_43                      = 43,
    SSH_MSG_KEX_44                      = 44,
    SSH_MSG_KEX_45                      = 45,
    SSH_MSG_KEX_46                      = 46,
    SSH_MSG_KEX_47                      = 47,
    SSH_MSG_KEX_48                      = 48,
    SSH_MSG_KEX_49                      = 49,
    SSH_MSG_USERAUTH_REQUEST            = 50, // [SSH-USERAUTH]
    SSH_MSG_USERAUTH_FAILURE            = 51, // [SSH-USERAUTH]
    SSH_MSG_USERAUTH_SUCCESS            = 52, // [SSH-USERAUTH]
    SSH_MSG_USERAUTH_BANNER             = 53, // [SSH-USERAUTH]
    SSH_MSG_GLOBAL_REQUEST              = 80, // [SSH-CONNECT]
    SSH_MSG_REQUEST_SUCCESS             = 81, // [SSH-CONNECT]
    SSH_MSG_REQUEST_FAILURE             = 82, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_OPEN                = 90, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION   = 91, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_OPEN_FAILURE        = 92, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_WINDOW_ADJUST       = 93, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_DATA                = 94, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_EXTENDED_DATA       = 95, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_EOF                 = 96, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_CLOSE               = 97, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_REQUEST             = 98, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_SUCCESS             = 99, // [SSH-CONNECT]
    SSH_MSG_CHANNEL_FAILURE             = 100 // [SSH-CONNECT]
  };

public:
  SSHMessage(unsigned char* buffer, int bufferSize);
  virtual ~SSHMessage(void);

  bool setMessageType(SSHMessageType type);

  SSHMessageType getMessageType(void) const;
  unsigned char* getMessage(int& messageSize) const;

  virtual zString toString(void) const;

  static char const* convSSHMessageTypeToChars(SSHMessageType type);

protected:
  virtual void impl_initPacket(void);

  // Skip bytes.
  // @return number of bytes skipped
  static int skipBytes(int bytes, unsigned char** message, int& messageSize);
  // Skip a name list.
  // @return number of bytes skipped
  static int skipString(unsigned char** message, int& messageSize);
};

#endif // SSHMESSAGE_H__
