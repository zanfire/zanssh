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

#include "zString.h"

#include "zStringBuffer.h"
#include "zBuffer.h"
#include "zStringTokenizer.h"
#include "zVectorString.h"

#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>


zString::zString(void) : zObject() {
  init(NULL, 0);
}


zString::zString(zString* str) : zObject() {
  if (str != NULL) {
    init(str->getBuffer(), str->getLength());
  } 
  else {
    init(NULL, 0);
  }
}


zString::zString(char c) : zObject() {
  init(&c, 1);
}


zString::zString(char const* str) : zObject() {
  int len = str != NULL ? strlen(str) : 0;
  init(str, len);
}


zString::zString(char const* str, int length) : zObject() {
  init(str, length);
}

zString::zString(zStringBuffer const* strb) : zObject() {
  char* targetBuffer = NULL;
  if (strb->getLength() <= STATIC_BUFFER_SIZE) {
    targetBuffer = (char*)&_staticBuffer;
    _dynamicBuffer = NULL;
  } 
  else {
    _dynamicBuffer = new zBuffer(strb->getLength() + 1);
    targetBuffer = (char*)_dynamicBuffer->getBuffer();
    _staticBuffer[0] = 0x00;
  }

  int readBytes = 0;
  zStringBuffer::zBuffer* buffer = (zStringBuffer::zBuffer*)&(strb->first_);
  while(buffer != NULL) {
    memcpy(targetBuffer + readBytes, buffer->buffer_, buffer->length_);
    readBytes +=  buffer->length_;
    buffer = buffer->next_;
  }
  targetBuffer[readBytes] = 0x00;
  _length =  strb->getLength();
}


zString::zString(zBuffer* buffer) : zObject() {
  _dynamicBuffer = buffer;
  _dynamicBuffer->acquireReference();
  _staticBuffer[0] = 0x00;
  _length = buffer->getSize() - 1;
}
  

zString::zString(const zString& str) : zObject() {
  copyFrom(str);
}


zString::~zString(void) {
  if (_dynamicBuffer != NULL) {
    _dynamicBuffer->releaseReference();
  }
}


void zString::init(char const* str, int length) {
  length = strnlen(str, length);
  if (str == NULL) {
    _staticBuffer[0] = 0x00;
	  _dynamicBuffer = NULL;
  } 
  else if (length <= STATIC_BUFFER_SIZE) {
    memcpy(_staticBuffer, str, length);
    _staticBuffer[length] = 0x00;
	  _dynamicBuffer = NULL;
  } 
  else {
    _dynamicBuffer = new zBuffer(length + 1);
    memcpy(_dynamicBuffer->getBuffer(), str, length);
    _dynamicBuffer->getBuffer()[length] = 0x00;
    _staticBuffer[0] = 0x00;
  }
  _length = length;
}


zString& zString::operator=(const zString& rhs) {
  if (this != &rhs) {
    copyFrom(rhs);
  }

  return *this;
}

bool zString::equals(zString const& str) const {
  return compareTo(str) == 0;
}


int zString::compareTo(zString const& str) const {
  return strcmp(getBuffer(), str.getBuffer());
}

  
char* zString::getBuffer(void) const {
  if (_dynamicBuffer != NULL) {
    return (char*)_dynamicBuffer->getBuffer();
  }
  else {
    return (char*)&_staticBuffer;
  }
}


void zString::copyFrom(const zString& str) {
  _length = str._length;
  if(str._dynamicBuffer != NULL) {
    _dynamicBuffer = str._dynamicBuffer;
    _dynamicBuffer->acquireReference();
  }
  else {
    _dynamicBuffer = NULL;
    memcpy(_staticBuffer, str._staticBuffer, _length);
    _staticBuffer[_length] = 0x00;
  }
}


zString zString::substrig(int startPos, int length) const {
  if (startPos < 0 || startPos > getLength()) return zString();
  if (length < 0 || (startPos + length) > getLength()) return zString();
  return zString(getBuffer() + startPos, length);
}


int zString::indexOf(zString& str, int startPos) const {
  char* buffer = getBuffer();
  int l = str.getLength();
  char* strBuf = str.getBuffer();
  for (int i = startPos; i < _length; i += l) {
    // Check size
    if ((_length - i) > l) {
      if (memcmp(buffer + i, strBuf, l) == 0) {
        return i;
      }
    }
  }
  return -1;
}


int zString::lastIndexOf(zString& str, int endPos) const {
  char* buffer = getBuffer();
  for (int i = getLength() - str.getLength(); i >= endPos; i--) {
    if (memcmp(buffer + i, str.getBuffer(), str.getLength()) == 0) {
      return i;
    }
  }
  return -1;
}


zString zString::fromPascalString(unsigned char const* pascalString, int bufferSize, bool isInNetworkByteOrder) {
  if (bufferSize < 4) return zString();
  uint32_t length = ((uint32_t*)pascalString)[0];
  length = isInNetworkByteOrder ? ntohl(length) : length;
  if (bufferSize < (int)(length + 4)) return zString();
  return zString((char*)(pascalString + 4), length);
}
