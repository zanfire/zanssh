/******************************************************************************
 * Copyright 2011 Matteo Valdina
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

#ifndef ZLOGGER_H__
#define ZLOGGER_H__

#include "global.h"
#include "zObject.h"
#include "zString.h"
#include "zVector.h"

#include <stdarg.h>
#include <string.h>
#include <errno.h>

class zLoggerAppender;

static zVector g_loggers;


#define CHECK_FATAL(error, message) if (error != 0) { zLogger::getLogger("base")->fatal("Fatal error %d (%s), %s.", error, strerror(errno), message); }
#define ZLOGGER zLogger::getLogger("base")


/**
 */
class zLogger : public zObject {

public:
  enum LogLevel {
    LOG_LEVEL_NONE      = 0x00,
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
  };

protected:
  zString _loggerName;
  zVector _appenders;
  LogLevel _level;

public:
  static zLogger* getLogger(char const* loggerName);

  void setLevel(LogLevel level) { _level = level; }
  void addAppender(zLoggerAppender* appender);

  virtual bool equals(zObject* obj) const;

  void fatal(char const* format, ...);
  void error(char const* format, ...);
  void warn(char const* format, ...);
  void info(char const* format, ...);
  void debug(char const* format, ...);

  void log(LogLevel level, char const* format, va_list args);
  void log(LogLevel level, char const* format, ...);


protected:
  zLogger(char const* loggerName);
  virtual ~zLogger(void);

  void loadConfiguration();
};


#endif // ZLOGGER_H__
