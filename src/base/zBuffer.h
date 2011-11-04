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

#ifndef ZBUFFER_H__
#define ZBUFFER_H__

#include "global.h"
#include "zObject.h"

class zBuffer : public zObject {
protected:
  unsigned char* buffer_;
  int size_;
public:

  zBuffer(int size);
  virtual ~zBuffer(void);

  virtual unsigned char* getBuffer() const { return buffer_; }
  int getSize() const { return size_; }

protected:
  zBuffer(void);
};

#endif // ZBUFFER_H__
