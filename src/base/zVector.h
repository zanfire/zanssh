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

#ifndef VECTOR_H__
#define VECTOR_H__

#include "global.h"
#include "zObject.h"

#define VECTOR_SIZE_INCREMENT 6

class zMutex;

// Benefit from Object addRef and some check
class zVector : public zObject {
protected:
  zMutex* _mtx;
  zObject** _vector;
  int _count;
  int _size;

public:
  zVector(bool threadSafe = false, int initialSize = VECTOR_SIZE_INCREMENT);
  zVector(const zVector& obj);

  virtual ~zVector(void);

  zVector& operator=(const zVector& rhs);

  int getCount(void) const { return _count; }
  void append(zObject* element);
  void insertAt(int index, zObject* element);
  zObject* removeAt(int index);
  void removeAll(void);
  zObject* getAt(int index) const;
  zObject* getrAt(int index) const;
  int contains(zObject* element) const;

protected:
  void copyFrom(zVector const& vstr);
};

#endif

