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
#include <arpa/inet.h>



SSHPacket::SSHPacket(unsigned char* buffer, int bufferSize) : zObject() {
  _buffer = buffer;
  _bufferSize = bufferSize;
}


SSHPacket::~SSHPacket(void) {
}


void SSHPacket::initPacket() {
  memset(_buffer, 0x00, _bufferSize);

}


bool SSHPacket::setPacketLength(int length) {
  return false;
}


bool SSHPacket::setPaddingtLength(int length) {
  return false;
}


bool SSHPacket::setPayload(unsigned char* payload, int payloadSize) {
  return false;
}


bool SSHPacket::setRandomPadding(unsigned char* randomPadding, int randomPaddingSize) {
  return false;
}


bool SSHPacket::setMAC(unsigned char* mac, int macSize) {
  return false;
}


uint32_t SSHPacket::getPacketLength(void) const {
  // Sanity check.
  if (_bufferSize < 4) return 0;

  return ntohl(((uint32_t*)_buffer)[0]);
}


uint8_t SSHPacket::getPaddingtLength(void) const {
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
  return (getPacketLength() - getPaddingtLength() - 1);
}


unsigned char* SSHPacket::getRandomPadding(int& randomPaddingSize) const {
  // TODO: Sanity check!!!
  int payloadSize = getPayloadSize();
  randomPaddingSize = getPaddingtLength();
  return _buffer + payloadSize + 5;
}


unsigned char* SSHPacket::getMAC(int& macSize) const {
  macSize = 0;
  // TODO: Sanity check!!!
  int bytes = getPayloadSize() + getPaddingtLength();
  return _buffer + bytes + 5;
}


zString SSHPacket::toString(void) const {
  zStringBuffer strb;
  strb.append("Packet length: ");
  strb.append(getPacketLength());
  strb.append("Padding length: ");
  strb.append(getPaddingtLength());
  strb.append("Payload length: ");
  strb.append(getPayloadSize());

  int payloadSize = 0;
  unsigned char* payload = getPayload(payloadSize);

  strb.append(zString((char*)payload, payloadSize));
  return strb.toString();
}
