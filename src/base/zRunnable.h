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

#ifndef RUNNABLE_H__
#define RUNNABLE_H__

#include "global.h"
#include "zObject.h"

class zRunnable : virtual public zObject {
public:
	zRunnable(void) : zObject() {}
	virtual ~zRunnable(void) {}

	virtual int run(void* param) = 0;
};

#endif // RUNNABLE_H__
