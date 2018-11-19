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
#include <stdio.h>
#include <time.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <string.h>
#include "htp_audit_filter.h"
#include "htp_audit_vars.h"
#include "cJSON.h"

/*
根据传入的审计类型，构造输出的审计字符串，并进行输出
每个函数对应一个审计事件的类型
*/

/*
  关于mysql audit审计开发中一些事情的描述。
  1、审计分为两个大类，general和connection。前者发生在sql语句的执行时（待定），后者发生在连接时。
  2、general类型的分类说明。
  2-1、MYSQL_AUDIT_GENERAL_ERROR:发生错误的时候进行的审计
  2-2、MYSQL_AUDIT_GENERAL_RESULT:客户端的命令执行后无错误的审计
  2-3、MYSQL_AUDIT_GENERAL_STATUS:每个命令执行后都会进行的审计
*/

/*
  connection类型，对应plugin_audi.h中的connection class
*/
/*
  审计连接信息
  审计信息
  {
  "host":"client host"
  , "ip":"clinet ip"
  , "user":"mysql user"
  }
*/
void audit_connection_connect(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_CONNECT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);
  //  sprintf(now, "%s", "2015-2-3 08:10 25");

  //TODO : build audit info from event
  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("connect"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));
  cJSON_AddItemToObject(root, "connection type",
                        cJSON_CreateNumber(event->connection_type));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_connection_disconnect(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_DISCONNECT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("disconnect"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));
  cJSON_AddItemToObject(root, "connection type",
                        cJSON_CreateNumber(event->connection_type));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_connection_change_user(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_CHANGE_USER);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("change user"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));
  cJSON_AddItemToObject(root, "connection type",
                        cJSON_CreateNumber(event->connection_type));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_connection_pre_authenticate(const struct mysql_event_connection *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_CONNECTION_PRE_AUTHENTICATE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("connection"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("pre authenticate"));
  if (event->host.str != NULL)
    cJSON_AddItemToObject(root, "host", cJSON_CreateString(event->host.str));
  if (event->ip.str != NULL)
    cJSON_AddItemToObject(root, "ip", cJSON_CreateString(event->ip.str));
  if (event->user.str != NULL)
    cJSON_AddItemToObject(root, "user", cJSON_CreateString(event->user.str));
  cJSON_AddItemToObject(root, "connection type",
                        cJSON_CreateNumber(event->connection_type));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}


/*
  普通类型，对应plugin_audit.h中的general class
*/
/*

 */
void audit_general_log(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_LOG);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("log"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));


  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_general_error(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_ERROR);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("error"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));
  if (event->general_command.str != NULL)
    cJSON_AddItemToObject(root, "error msg",
                          cJSON_CreateString(event->general_command.str));


  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetELogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_general_status(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_STATUS);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("status"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_general_result(const struct mysql_event_general *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GENERAL_RESULT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("general"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("result"));
  if (event->general_user.str != NULL)
    cJSON_AddItemToObject(root, "user",
                          cJSON_CreateString(event->general_user.str));
  if (event->general_host.str != NULL)
    cJSON_AddItemToObject(root, "host",
                          cJSON_CreateString(event->general_host.str));
  if (event->general_ip.str != NULL)
    cJSON_AddItemToObject(root, "ip",
                          cJSON_CreateString(event->general_ip.str));
  if (event->general_sql_command.str != NULL)
    cJSON_AddItemToObject(root, "command_class",
                          cJSON_CreateString(event->general_sql_command.str));
  if (event->general_query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->general_query.str));
  cJSON_AddItemToObject(root, "code",
                        cJSON_CreateNumber(event->general_error_code));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}


//new audit feature,added by gqhao 2018-10-08

// AUDIT_PARSET PROCESS PART
void audit_parse_preparse(const struct mysql_event_parse *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_PARSE_PREPARSE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("parse"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("preparse"));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->query.str));
  if (event->flags != NULL)
    cJSON_AddItemToObject(root, "pluginflag", cJSON_CreateNumber(*(event->flags)));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_parse_postparse(const struct mysql_event_parse *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_PARSE_POSTPARSE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("parse"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("postparse"));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext",
                          cJSON_CreateString(event->query.str));
  if (event->flags != NULL)
    cJSON_AddItemToObject(root, "pluginflag", cJSON_CreateNumber(*(event->flags)));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}


// MYSQL_AUDIT_AUTHORIZATION_USER


void audit_authorization_user(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_USER);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("user"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_authorization_db(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_DB);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("db"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_authorization_table(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_TABLE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("table"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_authorization_column(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_COLUMN);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("column"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_authorization_procedure(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_PROCEDURE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("procedure"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_authorization_proxy(const struct mysql_event_authorization *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_AUTHORIZATION_PROXY);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("authorization"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("proxy"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->database.str != NULL)
    cJSON_AddItemToObject(root, "database", cJSON_CreateString(event->database.str));
  if (event->table.str != NULL)
    cJSON_AddItemToObject(root, "table", cJSON_CreateString(event->table.str));
  cJSON_AddItemToObject(root, "requested_privilege", cJSON_CreateNumber(event->requested_privilege));
  cJSON_AddItemToObject(root, "granted_privilege", cJSON_CreateNumber(event->granted_privilege));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

//MYSQL_AUDIT_SERVER_SHUTDOWN_ALL

void audit_server_shutdown_shutdown(const struct mysql_event_server_shutdown *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_SERVER_SHUTDOWN_SHUTDOWN);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("shutdown"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("shutdown"));
  cJSON_AddItemToObject(root, "code", cJSON_CreateNumber(event->exit_code));
  cJSON_AddItemToObject(root, "reason", cJSON_CreateNumber(event->reason));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}
//case mysql server startup error,becase of mysql's bug,startup argvs error
/*
void audit_server_startup_startup(const struct mysql_event_server_startup *event) {
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_SERVER_STARTUP_STARTUP);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);
  char start_para[3000] = {0};
  for (unsigned int i = 0; i < event->argc; i++, strcat(start_para, event->argv[i]));
  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("startup"));
  cJSON_AddItemToObject(root, "start_paras", cJSON_CreateString(start_para));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetELogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}
*/
//MYSQL_AUDIT_COMMAND_ALL

void audit_command_start(const struct mysql_event_command *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_COMMAND_START);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("command"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("start"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "commandid", cJSON_CreateNumber(event->command_id));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_command_end(const struct mysql_event_command *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_COMMAND_END);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("command"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("end"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "commandid", cJSON_CreateNumber(event->command_id));

  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

//MYSQL_AUDIT_QUERY_ALL

void audit_query_start(const struct mysql_event_query *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_QUERY_START);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("query"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("start"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_query_nested_start(const struct mysql_event_query *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_QUERY_NESTED_START);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("query"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("nested start"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_query_status_end(const struct mysql_event_query *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_QUERY_STATUS_END);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("query"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("end"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_query_nested_status_end(const struct mysql_event_query *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_QUERY_NESTED_STATUS_END);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("query"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("nested db"));
  cJSON_AddItemToObject(root, "status", cJSON_CreateNumber(event->status));
  cJSON_AddItemToObject(root, "connectionid", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sqlcommandid", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

//MYSQL_AUDIT_TABLE_ACCESS_ALL

void audit_table_access_read(const struct mysql_event_table_access *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_TABLE_ACCESS_READ);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("table access"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("read"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->table_database.length > 0)
    cJSON_AddItemToObject(root, "table_database", cJSON_CreateString(event->table_database.str));
  if (event->table_name.length > 0)
    cJSON_AddItemToObject(root, "table_name", cJSON_CreateString(event->table_name.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_table_access_insert(const struct mysql_event_table_access *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_TABLE_ACCESS_INSERT);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("table_access"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("insert"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->table_database.length > 0)
    cJSON_AddItemToObject(root, "table_database", cJSON_CreateString(event->table_database.str));
  if (event->table_name.length > 0)
    cJSON_AddItemToObject(root, "table_name", cJSON_CreateString(event->table_name.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_table_access_update(const struct mysql_event_table_access *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_TABLE_ACCESS_UPDATE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("table_access"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("update"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->table_database.length > 0)
    cJSON_AddItemToObject(root, "table_database", cJSON_CreateString(event->table_database.str));
  if (event->table_name.length > 0)
    cJSON_AddItemToObject(root, "table_name", cJSON_CreateString(event->table_name.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_table_access_delete(const struct mysql_event_table_access *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_TABLE_ACCESS_DELETE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("table_access"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("delete"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "sqltext", cJSON_CreateString(event->query.str));
  if (event->table_database.length > 0)
    cJSON_AddItemToObject(root, "table_database", cJSON_CreateString(event->table_database.str));
  if (event->table_name.length > 0)
    cJSON_AddItemToObject(root, "table_name", cJSON_CreateString(event->table_name.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

//MYSQL_AUDIT_GLOBAL_VARIABLE_ALL

void audit_global_variable_get(const struct mysql_event_global_variable *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GLOBAL_VARIABLE_GET);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("global variable"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("get"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->variable_name.length > 0)
    cJSON_AddItemToObject(root, "variable name", cJSON_CreateString(event->variable_name.str));
  if (event->variable_value.length > 0)
    cJSON_AddItemToObject(root, "variable value", cJSON_CreateString(event->variable_value.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_global_variable_set(const struct mysql_event_global_variable *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_GLOBAL_VARIABLE_SET);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("global variable"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("set"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->variable_name.length > 0)
    cJSON_AddItemToObject(root, "variable name", cJSON_CreateString(event->variable_name.str));
  if (event->variable_value.length > 0)
    cJSON_AddItemToObject(root, "variable value", cJSON_CreateString(event->variable_value.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}

void audit_stored_program_event(const struct mysql_event_stored_program *event)
{
  DBUG_ASSERT(event->event_subclass == MYSQL_AUDIT_STORED_PROGRAM_EXECUTE);

  char current_str[100];
  //to do : 获取当前时间
  time_t current;
  struct tm current_broken;
  current = time(NULL);
  localtime_r(&current, &current_broken);

  strftime(current_str, sizeof(current_str), "%F %T", &current_broken);

  cJSON *root;
  root = cJSON_CreateObject();
  cJSON_AddItemToObject(root, "timestamp", cJSON_CreateString(current_str));
  cJSON_AddItemToObject(root, "type", cJSON_CreateString("stored program"));
  cJSON_AddItemToObject(root, "sub type", cJSON_CreateString("execute"));
  cJSON_AddItemToObject(root, "connection_id", cJSON_CreateNumber(event->connection_id));
  cJSON_AddItemToObject(root, "sql_command_id", cJSON_CreateNumber(event->sql_command_id));
  if (event->query.length > 0)
    cJSON_AddItemToObject(root, "query", cJSON_CreateString(event->query.str));
  if (event->name.length > 0)
    cJSON_AddItemToObject(root, "name", cJSON_CreateString(event->name.str));
  //获得json字符串，输出到审计日志
  char *json_str = cJSON_Print(root);
  Logger::GetLogger()->Write(json_str, ",");

  //释放资源
  cJSON_Delete(root);
  free(json_str);
}
