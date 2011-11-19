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
 *  uint32                                          packet_length
 *  byte                                            padding_length
 *  byte[n1 = packet_length - padding_length - 1]   payload
 *  byte[padding_length]                            random padding
 *  byte[mac_length]                                mac
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
  int _contentSize;

public:
  SSHPacket(unsigned char* buffer, int bufferSize);
  virtual ~SSHPacket(void);

  // Initializes SSH packet with empty data.
  void initPacket(void);
  void finalize(void);

  //
  // Setters
  //
  bool setPacketLength(uint32_t length);
  bool setPaddingLength(uint8_t length);
  bool setPayload(unsigned char* payload, int payloadSize);
  bool setPadding(unsigned char* randomPadding, int randomPaddingSize);
  bool setMAC(unsigned char* mac, int macSize);

  //
  // Getters
  //
  uint32_t getPacketLength(void) const;
  unsigned char* getPayload(int& payloadSize) const;
  int getPayloadSize() const;
  unsigned char* getPadding(int& paddingSize) const;
  uint8_t getPaddingLength(void) const;
  unsigned char* getMAC(int& macSize) const;
  int getMACSize(void) const;

  //
  unsigned char* getBuffer(void) const { return _buffer; }
  int getBufferSize(void) const { return _bufferSize; }
  int getBufferContentSize(void) const { return _contentSize; }

  bool isValid(void);

  virtual zString toString(void) const;

protected:

  // Shift payload from "from" to "to" indexes.
  // Note from and to are related to the payload.
  bool shiftPayload(int from, int to);
  bool appendPayload(unsigned char* payload, int payloadSize);
  bool replaceNameList(unsigned char* oldNameList, zString const& newNameList);

  virtual void impl_initPacket(void) {}
};

#endif // SSHPACKET_H_
