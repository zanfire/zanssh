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

#ifndef SSHMESSAGEKEYDHREPLAY_H__
#define SSHMESSAGEKEYDHREPLAY_H__

#include "SSHMessage.h"

#include "zString.h"
#include "zVectorString.h"


/*
 * byte SSH_MSG_KEXDH_REPLY
 * string server public host key and certificates (K_S)
 * mpint f
 * string signature of H
 */
class SSHMessageKeyDHReplay : public SSHMessage {

public:
  SSHMessageKeyDHReplay(unsigned char* buffer, int bufferSize);
  virtual ~SSHMessageKeyDHReplay(void);

  //
  // Setter
  //

  //
  // Getter
  //


  virtual zString toString(void) const;

protected:
  virtual void impl_initPacket(void);
};

#endif // SSHMESSAGEKEYDHRELAY_H__
