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

#include "SSHMessageKeyDHInit.h"

#include "zStringBuffer.h"
#include "zStringTokenizer.h"

#include "zBigNum.h"

#include <arpa/inet.h>

SSHMessageKeyDHInit::SSHMessageKeyDHInit(unsigned char* buffer, int bufferSize) : SSHMessage(buffer, bufferSize) {
}


SSHMessageKeyDHInit::~SSHMessageKeyDHInit(void) {
}


bool SSHMessageKeyDHInit::setE(zBigNum) {
  return false;
}


bool SSHMessageKeyDHInit::getE(zBigNum& bignum) {
  int messageSize = -1;
  unsigned char* message = getMessage(messageSize);
  if (message == NULL || messageSize <= SSH_MSG_KEXINIT_COOKIE_SIZE) {
    return false;
  }

  if (message != NULL && messageSize >= 4) {
    int len = ntohl(((uint32_t*)message)[0]);
    if (messageSize != (len + 4)) return false;

    bignum.parseFromMPInt(message + 4, len);
  }
  return true;

}



void SSHMessageKeyDHInit::impl_initPacket(void) {
  SSHMessage::impl_initPacket();
  setMessageType(SSHMessage::SSH_MSG_KEX_30);
}


zString SSHMessageKeyDHInit::toString(void) const {
  zStringBuffer strb;
  strb.append(SSHMessage::toString());
  return strb.toString();
}
