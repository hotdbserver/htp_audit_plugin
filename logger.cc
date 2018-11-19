/*
   This software is developed and maintained by HOTPU.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

//#include "htp_audit.h"
#include <string.h>
#include<stdlib.h>
#include "htp_audit_vars.h"
#include "htp_audit_filter.h"

using namespace std;

#define LOG_BUFFER_SIZE (1024 * 8)

class LogBuffer
{
 public :
  LogBuffer(FILE *file);

  void Write(const char *msg, int msg_len);

  void Flush();

  //size是以KB计数的，4表示4KB
  int SetBufferSize(int size);

 private :
  char buffer_inner_[LOG_BUFFER_SIZE];
  char *buffer_;
  int buffer_size_;
  volatile int available_pos_;
  FILE *file_;

  void Buffer(const char *msg, int msg_len);
};

LogBuffer::LogBuffer(FILE *file)
{
  file_ = file;
  buffer_size_ = LOG_BUFFER_SIZE;
  buffer_ = buffer_inner_;
  available_pos_ = 0;
}

void LogBuffer::Write(const char *msg, int msg_len)
{
  if ((available_pos_ + msg_len) >= buffer_size_)
    Flush();
  if (msg_len >= buffer_size_) {
    fprintf(file_, "%s", msg);
    fflush(file_);
    return;
  }
  Buffer(msg, msg_len);
}

void LogBuffer::Flush()
{
  char *content = buffer_;
  if (available_pos_ == 0)
    return;
  fprintf(file_, "%s", content);
  fflush(file_);
  available_pos_ = 0;
}

void LogBuffer::Buffer(const char *msg, int msg_len)
{
  strncpy(buffer_ + available_pos_, msg, msg_len);
  available_pos_ += msg_len;
  buffer_[available_pos_] = 0;
}

int LogBuffer::SetBufferSize(int size)
{
  int byte_size = size * 1024;
  if (byte_size < LOG_BUFFER_SIZE)
    return 0;

  if (byte_size == LOG_BUFFER_SIZE) {
    Flush();

    if (buffer_ != buffer_inner_)
      free(buffer_);

    buffer_ = buffer_inner_;
    buffer_size_ = LOG_BUFFER_SIZE;

    return 0;
  }

  char *buffer_new = (char *) malloc(byte_size);
  if (buffer_new == NULL)
    return 1;

  Flush();

  if (buffer_ != buffer_inner_)
    free(buffer_);

  buffer_ = buffer_new;
  buffer_size_ = byte_size;

  return 0;
}

/*
  用于审计general类下的status子类和connection类事件的记录
 */
static Logger *logger = NULL;

/*用于审计genaral类下error的事件记录*/
static Logger *elogger = NULL;
static bool log_initialized = false;

int Logger::Initialize(const char *log, const char *elog, my_bool enable_buffer)
{
  logger = new Logger(log);
  logger->EnableBuffer(enable_buffer);
  elogger = new Logger(elog);
  elogger->EnableBuffer(enable_buffer);

  log_initialized = true;
  return 0;
}

int Logger::Deinitialize()
{
  if (!log_initialized)
    return 0;

  delete logger;
  delete elogger;
  log_initialized = false;
  return 0;
}

Logger *Logger::GetLogger()
{
  return logger;
}

Logger *Logger::GetELogger()
{
  return elogger;
}

int Logger::FlushNew()
{
  logger->FlushNewInner();
  elogger->FlushNewInner();

  return 0;
}

int Logger::SetBufferSize(int size)
{
  logger->SetBufferSizeInner(size);
  elogger->SetBufferSizeInner(size);

  return 0;
}

Logger::Logger(const char *path)
{
  file_name_ = strdup(path);

  enable_buffer_ = false;
  file_ = fopen(path, "a+");
  if (enable_buffer_)
    log_buffer_ = new LogBuffer(file_);
  else
    log_buffer_ = NULL;

  mysql_mutex_init(0, &lock_, MY_MUTEX_INIT_FAST);
}

Logger::~Logger()
{
  if (log_buffer_ != NULL) {
    log_buffer_->Flush();
    delete log_buffer_;
  }

  if (file_ != NULL)
    fclose(file_);

  if (file_name_)
    free(file_name_);

  mysql_mutex_destroy(&lock_);
}

void Logger::Write(const char *info, const char *splitter)
{
  if (file_ == NULL)
    return;

  Lock();
  if (enable_buffer_) {
    int info_len = strlen(info);
    log_buffer_->Write(info, info_len);

    if (splitter != NULL) {
      int splitter_len = strlen(splitter);
      log_buffer_->Write(splitter, splitter_len);
    }

  }
  else {
    if (splitter != NULL) {
      fprintf(file_, "%s%s", info, splitter);
    }
    else {
      fprintf(file_, "%s", info);
    }

    fflush(file_);
  }
  Unlock();
}

void Logger::EnableBuffer(bool enable)
{
  if (enable_buffer_ == enable)
    return;

  Lock();
  if (enable == true) {
    //打开开关
    if (log_buffer_ == NULL)
      log_buffer_ = new LogBuffer(file_);
  }
  else {
    //flush 全部内容
    log_buffer_->Flush();
  }
  Unlock();

  enable_buffer_ = enable;
}

int Logger::FlushNewInner()
{
  Lock();
  char file_name_new[512];

  if (enable_buffer_ == true) {
    log_buffer_->Flush();
    delete log_buffer_;
  }

  fclose(file_);
  time_t tm = time(NULL);
  sprintf(file_name_new, "%s.%d", file_name_, (int) tm);
  rename(file_name_, file_name_new);

  file_ = fopen(file_name_, "a+");
  if (enable_buffer_)
    log_buffer_ = new LogBuffer(file_);
  else
    log_buffer_ = NULL;

  Unlock();

  return 0;
}

int Logger::SetBufferSizeInner(int size)
{
  Lock();
  if (enable_buffer_ == true) {
    log_buffer_->SetBufferSize(size);
  }
  Unlock();

  return 0;
}
