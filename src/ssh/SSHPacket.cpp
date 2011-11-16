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

/**
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

#include "SSHPacket.h"

#include "zStringBuffer.h"

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>



SSHPacket::SSHPacket(unsigned char* buffer, int bufferSize) : zObject() {
  _buffer = buffer;
  _bufferSize = bufferSize;
  _contentSize = bufferSize;
}


SSHPacket::~SSHPacket(void) {
}


void SSHPacket::initPacket() {
  memset(_buffer, 0x00, _bufferSize);
  _contentSize = 5; // Packet length
  setPacketLength(1); // Padding is included.
  impl_initPacket();
}


bool SSHPacket::shiftPayload(int from, int to) {
  if (from < 0 || to < 0) return false;
  if (from == to) return true; // Do nothing.
  // Check sizes
  if ((uint32_t)from > getPacketLength() ) return false;

  int offset = abs(to - from);
  if (from < to) {
    if (_contentSize + offset  >= _bufferSize) return false;
    for (int i = _contentSize -1; i >= (to + 5); i--) {
      _buffer[i + offset] = _buffer[i];
    }
    _contentSize += offset;
    setPacketLength(getPacketLength() + offset);
  }
  else {
    for (int i = to -1; i < _contentSize; i++) {
    _buffer[i - offset] = _buffer[i];
    }
    _contentSize -= offset;
    setPacketLength(getPacketLength() - offset);
  }
  return true;
}


bool SSHPacket::appendPayload(unsigned char* payload, int payloadSize) {
  if (payloadSize < 0) return false;
  if (payload == NULL) return false;
  int currentPayloadSize = 0;
  unsigned char* buf = getPayload(currentPayloadSize);
  if (buf == NULL) return false;
  if (currentPayloadSize + payloadSize + 5 > _bufferSize) return false;
  if (shiftPayload(currentPayloadSize, currentPayloadSize + payloadSize)) {
     memcpy(buf + currentPayloadSize, payload, payloadSize);
     return true;
   }
   else {
     return false;
   }
}


bool SSHPacket::setPacketLength(uint32_t length) {
  if (_bufferSize < 4) return false;
  ((uint32_t*)_buffer)[0] = htonl(length);
  return true;
}


bool SSHPacket::setPaddingLength(uint8_t length) {
  if (_bufferSize < 5) return false;
  _buffer[4] = length;
  return true;
}


bool SSHPacket::setPayload(unsigned char* payload, int payloadSize) {
  if (payloadSize < 0) return false;
  if (payload == NULL) return false;
  // TODO: Improves this check.
  if (payloadSize + 5 > _bufferSize) return false;
  int currentPayloadSize = getPayloadSize();
  if (shiftPayload(currentPayloadSize, payloadSize)) {
    unsigned char* buf = getPayload(currentPayloadSize);
    if (buf == NULL) return false;
    memcpy(buf, payload, currentPayloadSize);
    return true;
  }
  else {
    return false;
  }
}


bool SSHPacket::setPadding(unsigned char* padding, int paddingSize) {
  if (padding == NULL) return false;
  if (paddingSize < 0) return false;

  int currentPaddingSize = 0;
  unsigned char* buf = getPadding(currentPaddingSize);
  int offset = abs(currentPaddingSize - paddingSize);
  if (currentPaddingSize < paddingSize) {
    if ((_contentSize + (paddingSize - currentPaddingSize)) > _bufferSize) return false;
    for (int i = _contentSize -1; i >= (_contentSize - getMACSize()); i--) {
      _buffer[i + offset] = _buffer[i];
    }
  }
  else {
    for (int i = (_contentSize - getMACSize() - offset); i <_contentSize; i++) {
      _buffer[i] = _buffer[i + offset];
    }
  }

  memcpy(buf, padding, paddingSize);
  _contentSize = _contentSize - currentPaddingSize + paddingSize;
  return true;
}


bool SSHPacket::setMAC(unsigned char* mac, int macSize) {
  if (mac == NULL) return false;
  if (macSize < 0) return false;

  int currentMACSize = 0;
  unsigned char* buf = getMAC(currentMACSize);
  if (currentMACSize < macSize) {
    // Sanity check
    if ((_contentSize + (macSize - currentMACSize)) > _bufferSize) return false;
  }

  memcpy(buf, mac, macSize);
  _contentSize = _contentSize - currentMACSize + macSize;
  return true;
}


uint32_t SSHPacket::getPacketLength(void) const {
  // Sanity check.
  if (_bufferSize < 4) return 0;

  return ntohl(((uint32_t*)_buffer)[0]);
}


uint8_t SSHPacket::getPaddingLength(void) const {
  // Sanity check.
  if (_bufferSize < 5) return 0;

  return _buffer[4];
}


unsigned char* SSHPacket::getPayload(int& payloadSize) const {
  //  byte[n1]    payload; n1 = packet_length - padding_length - 1
  int size = getPayloadSize();
  if (size < 0) return NULL;
  if (_bufferSize < size + 5) return NULL;

  payloadSize = size;
  return _buffer + 5;
}


int SSHPacket::getPayloadSize(void) const {
  if (getPacketLength() == 0 ) return -1;
  return (getPacketLength() - getPaddingLength() - 1);
}


unsigned char* SSHPacket::getPadding(int& paddingSize) const {
  // TODO: Sanity check!!!
  int payloadSize = getPayloadSize();
  paddingSize = getPaddingLength();
  return _buffer + payloadSize + 5;
}


unsigned char* SSHPacket::getMAC(int& macSize) const {
  macSize = getMACSize();
  int bytes = getPacketLength() + 4;
  if (bytes > _bufferSize || (bytes + macSize) > _bufferSize) {
    macSize = 0;
    return NULL;
  }
  return _buffer + bytes;
}


int SSHPacket::getMACSize(void) const {
  return (_contentSize - (getPacketLength() + 4));
}


zString SSHPacket::toString(void) const {
  zStringBuffer strb;
  strb.append("Packet length: ");
  strb.append(getPacketLength());
  strb.append(" Padding length: ");
  strb.append(getPaddingLength());
  strb.append(" Payload length: ");
  strb.append(getPayloadSize());
  return strb.toString();
}
