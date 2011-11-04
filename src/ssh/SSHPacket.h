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

#ifndef SSHPACKET_H__
#define SSHPACKET_H__

#include "global.h"
#include "zObject.h"
#include "zString.h"

/**
 * From RFC 4253
 *
 *  uint32      packet_length
 *  byte        padding_length
 *  byte[n1]    payload; n1 = packet_length - padding_length - 1
 *  byte[n2]    random padding; n2 = padding_length
 *  byte[m]     mac (Message Authentication Code - MAC); m = mac_length
 *
 *  packet_length
 *      The length of the packet in bytes, not including ’mac’ or the
 *      ’packet_length’ field itself.
 *  padding_length
 *      Length of ’random padding’ (bytes).
 *  payload
 *      The useful contents of the packet. If compression has been
 *      negotiated, this field is compressed. Initially, compression
 *      MUST be "none".
 *  random padding
 *      Arbitrary-length padding, such that the total length of
 *      (packet_length || padding_length || payload || random padding)
 *      is a multiple of the cipher block size or 8, whichever is
 *      larger. There MUST be at least four bytes of padding. The
 *      padding SHOULD consist of random bytes. The maximum amount of
 *      padding is 255 bytes.
 *  mac
 *      Message Authentication Code. If message authentication has
 *      been negotiated, this field contains the MAC bytes. Initially,
 *      the MAC algorithm MUST be "none".
 *
 */
class SSHPacket : zObject {
protected:
  unsigned char* _buffer;
  int _bufferSize;

public:
  SSHPacket(unsigned char* buffer, int bufferSize);
  virtual ~SSHPacket(void);

  bool setPacketLength(int length);
  bool setPaddingtLength(int length);
  bool setPayload(unsigned char* payload, int payloadSize);
  bool setRandomPadding(unsigned char* randomPadding, int randomPaddingSize);
  bool setMAC(unsigned char* mac, int macSize);

  uint32_t getPacketLength(void) const;
  uint8_t getPaddingtLength(void) const;
  unsigned char* getPayload(int& payloadSize) const;
  int getPayloadSize() const;
  unsigned char* getRandomPadding(int& randomPaddingSize) const;
  unsigned char* getMAC(int& macSize) const;

  zString toString(void) const;
};

#endif // SSHPACKET_H_
