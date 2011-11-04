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

#include "zLogger.h"

#include <stdio.h>
#include <stdlib.h>


#include "zLoggerAppenderConsole.h"


zLogger::zLogger(char const* loggerName) : zObject() {
  _loggerName = zString(loggerName);
  _level = LOG_LEVEL_INFO;
}


zLogger::~zLogger(void) {
  while(_appenders.getCount() > 0) {
    _appenders.removeAt(_appenders.getCount() - 1);
  }
}


zLogger* zLogger::getLogger(char const* loggerName) {
  zLogger* logger = new zLogger(loggerName);
  int index = g_loggers.contains(logger);
  if (index >= 0) {
    delete logger;
    return (zLogger*)g_loggers.getAt(index);
  }
  else {
    logger->loadConfiguration();
    return logger;
  }
}


void zLogger::loadConfiguration(void) {
  addAppender(new zLoggerAppenderConsole());
  setLevel(LOG_LEVEL_DEBUG);
}


bool zLogger::equals(zObject* obj) const {
  zLogger* logger = dynamic_cast<zLogger*>(obj);
  if (logger != NULL) {
    return logger->_loggerName.equals((zString*)&_loggerName);
  }
  return false;
}


void zLogger::addAppender(zLoggerAppender* appender) {
  if (appender == NULL) return;
  _appenders.append(appender);
}


void zLogger::fatal(char const* format, ...) {
  va_list args;
  va_start(args, format);
  log(LOG_LEVEL_FATAL, format, args);
  va_end(args);

  exit(EXIT_FAILURE);
}


void zLogger::error(char const* format, ...) {
  va_list args;
  va_start(args, format);
  log(LOG_LEVEL_ERROR, format, args);
  va_end(args);
}


void zLogger::info(char const* format, ...) {
  va_list ap;
  va_start(ap, format);
  log(LOG_LEVEL_INFO, format, ap);
  va_end(ap);
}


void zLogger::debug(char const* format, ...) {
  va_list args;
  va_start(args, format);
  log(LOG_LEVEL_DEBUG, format, args);
  va_end(args);
}


void zLogger::log(LogLevel level, char const* format, ...) {
  va_list args;
  va_start(args, format);
  log(level, format, args);
  va_end(args);
}

void zLogger::log(LogLevel level, char const* format, va_list args) {
  if (level < _level) return;
  char line[1024 * 4];
  line[0] = '\n';

  vsnprintf(line, sizeof(line), format, args);

  for (int i = 0; i < _appenders.getCount(); i++) {
    zLoggerAppender* appender = (zLoggerAppender*)_appenders.getrAt(i);
    appender->writeLine(line);
    appender->releaseReference();
  }
}
