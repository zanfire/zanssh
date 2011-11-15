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

#include "zStringBuffer.h"

#include <string.h>
#include <stdio.h>
#include <stdarg.h>


zStringBuffer::zStringBuffer(void) : zObject() {
  current_ = &first_;
  bufferCount_ = 1;
}


zStringBuffer::~zStringBuffer(void) {
  zBuffer* buffer = first_.next_;
  zBuffer* tmp = NULL;
  while(buffer != NULL) {
    tmp = buffer;
    buffer = buffer->next_;
    delete tmp;
  }
}

int zStringBuffer::getLength(void) const {
  return (bufferCount_ - 1) * STRINGBUFFER_CHUNK_SIZE + current_->length_;
}

void zStringBuffer::append(zString const& str) {
  append(str.getBuffer(), str.getLength());
}


void zStringBuffer::append(char const* str) {
  append(str, strlen(str));
}

void zStringBuffer::append(char const* str, int len) {
  if (current_->length_ + len + 1 >= STRINGBUFFER_CHUNK_SIZE) {
    int readBytes = 0;
    while (len > 0) {
      // CHECK THE FOLLOWING 2 lines.
      int tmp =  (STRINGBUFFER_CHUNK_SIZE - current_->length_);
      int chunk = len > tmp ? tmp : len;
      
      memcpy(current_->buffer_ + current_->length_, str + readBytes, chunk);
      current_->length_ += chunk;
      len -= chunk;
      readBytes += chunk;

      if (current_->length_ == STRINGBUFFER_CHUNK_SIZE) {
        current_->next_ = new zBuffer();
        current_ = current_->next_;
        bufferCount_++;
      } 
    }
  } 
  else {
    memcpy(current_->buffer_ + current_->length_, str, len);
    current_->length_ += len;
  }
}


void zStringBuffer::append(char c) {
  append(&c, 1);
}

void zStringBuffer::appendFormatted(char const* format, ...) {
  char line[1024 * 4];
  line[0] = '\n';

  va_list args;
  va_start(args, format);
  vsnprintf(line, sizeof(line), format, args);
  va_end(args);

  append(line);
}


void zStringBuffer::append(int value) {
  char buffer[10];
  snprintf(buffer, sizeof(buffer), "%d", value);
  append(buffer);
}


void zStringBuffer::append(unsigned int value) {
  char buffer[10];
  snprintf(buffer, sizeof(buffer), "%u", value);
  append(buffer);
}



zString zStringBuffer::toString() const {
  return zString(this);
}
