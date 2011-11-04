/******************************************************************************
 * Copyright 2009 Matteo Valdina
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

#ifndef STRINGBUFFER_H__
#define STRINGBUFFER_H__

#include "global.h"
#include "zObject.h"
#include "zString.h"

#define STRINGBUFFER_CHUNK_SIZE 256

class zStringBuffer : public zObject {

  friend class zString;

private:
  class zBuffer {
  public:
    char buffer_[STRINGBUFFER_CHUNK_SIZE];
    int length_;
    zBuffer* next_;
  public:
    zBuffer(void) : length_(0), next_(NULL) {}
  };

private:
  zBuffer first_;
  zBuffer* current_;
  int bufferCount_;
public:
  zStringBuffer(void);
  virtual ~zStringBuffer(void);

  int getLength() const;
  void append(zString const& str);
  void append(char const* str);
  void append(char const* str, int len);
  void append(char c);
  void append(short c);
  //void append(unsigned short c);
  void append(int c);
  void append(unsigned int c);
  //void append(long c);
  //void append(unsigned long c);

  zString toString() const;

private:
};

#endif // STRINGBUFFER_H__
