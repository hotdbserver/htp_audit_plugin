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
#include <string.h>
#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>
//#include "htp_audit.h"
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "log.h"
#include "htp_audit_vars.h"
#include "htp_audit_filter.h"
/* 变量 */
/*command line/option file/system variables*/
#define MAX_ADD_RULE_LENGTH 1024
#define DEFAULT_LOG_FILE "htp_audit.log"
#define DEFAULT_ERROR_LOG_FILE "htp_audit_error.log"

#define HTP_AUDIT_CONFIG_MAX_FILE_NAME 1024

char htp_audit_log_file[HTP_AUDIT_CONFIG_MAX_FILE_NAME + 1];
char htp_audit_error_log_file[HTP_AUDIT_CONFIG_MAX_FILE_NAME + 1];

char *log_file = NULL;
char *error_log_file = NULL;
my_bool enable_buffer = FALSE;

static char *rules = NULL;
static char *add_rule = NULL;
static char *remove_rule = NULL;

static my_bool flush_log = FALSE;
static int buffer_size = 32;  //measure in KB.32 means 32KB
static char version_inner[] = HTP_AUDIT_VERSION;
static char *version = version_inner;

extern list<int> filters;
extern filter_item_t filter_items[];

static int rules2str_buffer_init(rules2str_buffer_t *buffer)
{
  buffer->buffer = buffer->buffer_inner;
  buffer->buffer_size = RULES2STR_BUFFER_LEN;
  buffer->buffer[0] = 0;
  buffer->occupied_bytes = 0;
  return 0;
}

static void rules2str_buffer_deinit(rules2str_buffer_t *buffer)
{
  if (buffer->buffer != buffer->buffer_inner)
    free(buffer->buffer);
}

static int rules2str_buffer_reset(rules2str_buffer_t *buffer)
{
  if (buffer->buffer != buffer->buffer_inner)
    free(buffer->buffer);
  rules2str_buffer_init(buffer);
  return 0;
}

const char *general_events[] = {
    HTP_AUDIT_EVENT_GENERAL_SUB_LOG,
    HTP_AUDIT_EVENT_GENERAL_SUB_ERROR,
    HTP_AUDIT_EVENT_GENERAL_SUB_RESULT,
    HTP_AUDIT_EVENT_GENERAL_SUB_STATUS
};

const char *connection_events[] = {
    HTP_AUDIT_EVENT_CONNECTION_SUB_CONNECT,
    HTP_AUDIT_EVENT_CONNECTION_SUB_DISCONNECT,
    HTP_AUDIT_EVENT_CONNECTION_SUB_CHANGE_USER
};

const char *parse_events[] = {
    HTP_AUDIT_EVENT_PARSE_SUB_PREPARSE,
    HTP_AUDIT_EVENT_PARSE_SUB_POSTPARSE
};

const char *authorization_events[] = {
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_USER,
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_DB,
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_TABLE,
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_COLUMN,
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_PROCEDURE,
    HTP_AUDIT_EVENT_AUTHORIZAITON_SUB_PROXY
};

const char *table_access_events[] = {
    HTP_AUDIT_EVENT_TABLE_ACCESS_SUB_READ,
    HTP_AUDIT_EVENT_TABLE_ACCESS_SUB_INSERT,
    HTP_AUDIT_EVENT_TABLE_ACCESS_SUB_UPDATE,
    HTP_AUDIT_EVENT_TABLE_ACCESS_SUB_DELETE
};

const char *global_variable_events[] = {
    HTP_AUDIT_EVENT_GLOBAL_VARIABLE_SUB_GET,
    HTP_AUDIT_EVENT_GLOBAL_VARIABLE_SUB_SET
};

const char *query_events[] = {
    HTP_AUDIT_EVENT_QUERY_SUB_START,
    HTP_AUDIT_EVENT_QUERY_SUB_NESTED_START,
    HTP_AUDIT_EVENT_QUERY_SUB_STATUS_END,
    HTP_AUDIT_EVENT_QUERY_SUB_NESTED_STATUS_END
};

const char *command_events[] = {
    HTP_AUDIT_EVENT_COMMAND_SUB_START,
    HTP_AUDIT_EVENT_COMMAND_SUB_END
};

static void htp_audit_rule_2_str(
    filter_item_t *item, char *buffer, int size)
{
  char *buffer_index = buffer;

  //name
  strcpy(buffer_index, HTP_AUDIT_RULE_KEY_NAME);
  buffer_index += strlen(HTP_AUDIT_RULE_KEY_NAME);
  strcpy(buffer_index, "=");
  buffer_index += 1;
  strcpy(buffer_index, item->name);
  buffer_index += strlen(item->name);
  //host
  if (item->host_length != 0) {
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    strcpy(buffer_index, HTP_AUDIT_RULE_KEY_HOST);
    buffer_index += strlen(HTP_AUDIT_RULE_KEY_HOST);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->host);
    buffer_index += item->host_length;
  }
  //user
  if (item->user_length != 0) {
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    strcpy(buffer_index, HTP_AUDIT_RULE_KEY_USER);
    buffer_index += strlen(HTP_AUDIT_RULE_KEY_USER);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->user);
    buffer_index += item->user_length;
  }
  //event
  strcpy(buffer_index, "\n");
  buffer_index += 1;
  if (item->audit_all_event == true) {
    //all event setted
    const char *audit_all = "event=all";
    strcpy(buffer_index, audit_all);
    buffer_index += strlen(audit_all);
  }
  else {
    const char *event_head = "event={";
    strcpy(buffer_index, event_head);
    buffer_index += strlen(event_head);
    bool need_semicolon = false;

    //general event
    if (item->audit_all_general) {
      const char *all_general = HTP_AUDIT_EVENT_GENERAL_CLASS;
      strcpy(buffer_index, all_general);
      buffer_index += strlen(all_general);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      need_semicolon = false;
      strcpy(buffer_index, HTP_AUDIT_EVENT_GENERAL_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_GENERAL_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_GENERAL_EVENTS; i++) {
        if (item->general_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, general_events[i]);
          buffer_index += strlen(general_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }
    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_GENERAL_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //connection event
    if (item->audit_all_connection) {
      const char *all_connection = HTP_AUDIT_EVENT_CONNECTION_CLASS;
      strcpy(buffer_index, all_connection);
      buffer_index += strlen(all_connection);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_CONNECTION_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_CONNECTION_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_CONNECTION_EVENTS; i++) {
        if (item->connection_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, connection_events[i]);
          buffer_index += strlen(connection_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }
    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_CONNECTION_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //parse event
    if (item->audit_all_parse) {
      const char *all_parse = HTP_AUDIT_EVENT_PARSE_CLASS;
      strcpy(buffer_index, all_parse);
      buffer_index += strlen(all_parse);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_PARSE_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_PARSE_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_PARSE_EVENTS; i++) {
        if (item->parse_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, parse_events[i]);
          buffer_index += strlen(parse_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_PARSE_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //authorization event
    if (item->audit_all_authorization) {
      const char *all_authorization = HTP_AUDIT_EVENT_AUTHORIZATION_CLASS;
      strcpy(buffer_index, all_authorization);
      buffer_index += strlen(all_authorization);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_AUTHORIZATION_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_AUTHORIZATION_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_AUTHORIZATION_EVENTS; i++) {
        if (item->authorization_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, authorization_events[i]);
          buffer_index += strlen(authorization_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_AUTHORIZATION_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //table_access event
    if (item->audit_all_table_access) {
      const char *all_table_access = HTP_AUDIT_EVENT_TABLE_ACCESS_CLASS;
      strcpy(buffer_index, all_table_access);
      buffer_index += strlen(all_table_access);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_TABLE_ACCESS_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_TABLE_ACCESS_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_TABLE_ACCESS_EVENTS; i++) {
        if (item->table_access_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, table_access_events[i]);
          buffer_index += strlen(table_access_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_TABLE_ACCESS_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //global_variable event
    if (item->audit_all_global_variable) {
      const char *all_global_variable = HTP_AUDIT_EVENT_GLOBAL_VARIABLE_CLASS;
      strcpy(buffer_index, all_global_variable);
      buffer_index += strlen(all_global_variable);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_GLOBAL_VARIABLE_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_GLOBAL_VARIABLE_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_GLOBAL_VARIABLE_EVENTS; i++) {
        if (item->global_variable_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, global_variable_events[i]);
          buffer_index += strlen(global_variable_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_GLOBAL_VARIABLE_CLASS);
      *buffer_index = 0;
    }
    need_semicolon = false;

    //command event
    if (item->audit_all_command) {
      const char *all_command = HTP_AUDIT_EVENT_COMMAND_CLASS;
      strcpy(buffer_index, all_command);
      buffer_index += strlen(all_command);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_COMMAND_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_COMMAND_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_COMMAND_EVENTS; i++) {
        if (item->command_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, command_events[i]);
          buffer_index += strlen(command_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_COMMAND_CLASS);
      *buffer_index = 0;
    }

    need_semicolon = false;

    //query event
    if (item->audit_all_query) {
      const char *all_query = HTP_AUDIT_EVENT_QUERY_CLASS;
      strcpy(buffer_index, all_query);
      buffer_index += strlen(all_query);
      strcpy(buffer_index, "}");
      buffer_index++;
      need_semicolon = true;
    }
    else {
      strcpy(buffer_index, HTP_AUDIT_EVENT_QUERY_CLASS);
      buffer_index += strlen(HTP_AUDIT_EVENT_QUERY_CLASS);
      strcpy(buffer_index, ":");
      buffer_index++;
      for (int i = 0; i < MAX_FILTER_QUERY_EVENTS; i++) {
        if (item->query_events[i] == EVENT_SETTED) {
          //  if (need_semicolon) {
          //    strcpy(buffer_index, ";");
          //   buffer_index++;
          // }
          strcpy(buffer_index, query_events[i]);
          buffer_index += strlen(query_events[i]);
          strcpy(buffer_index, ",");
          buffer_index++;
          need_semicolon = true;
        }
      }
    }

    if (need_semicolon) {
      buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_QUERY_CLASS);
      *buffer_index = 0;
    }

    //need_semicolon=false;

    strcpy(buffer_index, HTP_AUDIT_EVENT_STARTUP_CLASS);
    buffer_index += strlen(HTP_AUDIT_EVENT_STARTUP_CLASS);
    if (item->audit_event_startup) {
      //need_semicolon=true;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      //buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_STARTUP_CLASS);
      *buffer_index = 0;
    }

    //need_semicolon=false;
    strcpy(buffer_index, HTP_AUDIT_EVENT_SHUTDOWN_CLASS);
    buffer_index += strlen(HTP_AUDIT_EVENT_SHUTDOWN_CLASS);

    if (item->audit_event_startup) {
//      need_semicolon=true;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      //buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_SHUTDOWN_CLASS);
      *buffer_index = 0;
    }

    //need_semicolon=false;
    strcpy(buffer_index, HTP_AUDIT_EVENT_STORED_PROGRAM_CLASS);
    buffer_index += strlen(HTP_AUDIT_EVENT_STORED_PROGRAM_CLASS);
    if (item->audit_event_stored_program) {
      //buffer_index--;
      strcpy(buffer_index, "};{");
      buffer_index += 3;
    }
    else {
      //buffer_index--;
      buffer_index -= strlen(HTP_AUDIT_EVENT_STORED_PROGRAM_CLASS);
      *buffer_index = 0;
    }

    if (*(buffer_index - 1) == '{') {
      buffer_index -= 2;
      *buffer_index = 0;
    }
    //buffer_index--;
    // *buffer_index=0;

  }
  //command
  if (item->command_length != 0) {
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    strcpy(buffer_index, HTP_AUDIT_RULE_KEY_CMD);
    buffer_index += strlen(HTP_AUDIT_RULE_KEY_CMD);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->command);
    buffer_index += item->command_length;
  }
  //sql_command
  if (item->sql_command_length != 0) {
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    strcpy(buffer_index, HTP_AUDIT_RULE_KEY_SQL_CMD);
    buffer_index += strlen(HTP_AUDIT_RULE_KEY_SQL_CMD);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->sql_command);
    buffer_index += item->sql_command_length;
  }
  //sql_keyword
  if (item->sql_keyword_length != 0) {
    strcpy(buffer_index, "\n");
    buffer_index += 1;
    strcpy(buffer_index, HTP_AUDIT_RULE_KEY_SQL_KEYWORD);
    buffer_index += strlen(HTP_AUDIT_RULE_KEY_SQL_KEYWORD);
    strcpy(buffer_index, "=");
    buffer_index += 1;
    strcpy(buffer_index, item->sql_keyword);
    buffer_index += item->sql_keyword_length;
  }
  strcpy(buffer_index, "\n");
  buffer_index += 1;
}

static void rules2str_buffer_write(const char *rule, rules2str_buffer_t *buffer)
{
  int len = strlen(rule);
  if ((buffer->occupied_bytes + len) >= buffer->buffer_size) {
    //TODO:重新分配空间
  }
  char *start = buffer->buffer + buffer->occupied_bytes;
  strcpy(start, rule);
  buffer->occupied_bytes += len;
}

static void htp_audit_rules_2_str(rules2str_buffer_t *buffer)
{
  char temp_rule_buffer[RULE_ITEM_BUFFER_LEN];

  rules2str_buffer_reset(buffer);
  list<int>::iterator it;
  filter_item_t *item;
  for (it = filters.begin(); it != filters.end(); it++) {
    int pos = *it;
    item = filter_items + pos;
    htp_audit_rule_2_str(item, temp_rule_buffer, sizeof(temp_rule_buffer));
    rules2str_buffer_write(temp_rule_buffer, buffer);
  }
}

#define HTP_AUDIT_VAR(x) static volatile int64_t number_of_calls_ ## x;


/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
HTP_AUDIT_VAR(general_log)
HTP_AUDIT_VAR(general_error)
HTP_AUDIT_VAR(general_result)
HTP_AUDIT_VAR(general_status)

/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
HTP_AUDIT_VAR(connection_connect)
HTP_AUDIT_VAR(connection_disconnect)
HTP_AUDIT_VAR(connection_change_user)
HTP_AUDIT_VAR(connection_pre_authenticate)
//HTP_AUDIT_VAR(connection_pre_authenticate)

/* Count MYSQL_AUDIT_PARSE_CLASS event instances */
HTP_AUDIT_VAR(parse_preparse)
HTP_AUDIT_VAR(parse_postparse)

/* Count MYSQL_AUDIT_COMMAND_CLASS event instances */
HTP_AUDIT_VAR(command_start)
HTP_AUDIT_VAR(command_end)

/* Count MYSQL_AUDIT_AUTHORIZATION_CLASS event instances */
HTP_AUDIT_VAR(authorization_user)
HTP_AUDIT_VAR(authorization_db)
HTP_AUDIT_VAR(authorization_table)

/* Count MYSQL_AUDIT_QUERY_CLASS event instances */
HTP_AUDIT_VAR(query_start)
HTP_AUDIT_VAR(query_nested_start)
HTP_AUDIT_VAR(query_status_end)
HTP_AUDIT_VAR(query_nested_status_end)

/* Count MYSQL_AUDIT_SERVER_STARTUP_CLASS event instances */
HTP_AUDIT_VAR(server_startup)

HTP_AUDIT_VAR(authorization_column)
HTP_AUDIT_VAR(authorization_procedure)
HTP_AUDIT_VAR(authorization_proxy)
/* Count MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS event instances */
HTP_AUDIT_VAR(server_shutdown)

/* Count MYSQL_AUDIT_TABLE_ACCESS_CLASS event instances */
HTP_AUDIT_VAR(table_access_insert)
HTP_AUDIT_VAR(table_access_delete)
HTP_AUDIT_VAR(table_access_update)
HTP_AUDIT_VAR(table_access_read)

/* Count MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS event instances */
HTP_AUDIT_VAR(global_variable_get)
HTP_AUDIT_VAR(global_variable_set)

/* Count MYSQL_AUDIT_STORED_PROGRAM event instances */
HTP_AUDIT_VAR(stored_program)



/* 状态 */
/*传入插件的事件统计*/
/* status variables */
static volatile int64_t number_of_calls; /* for SHOW STATUS, see below */
/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
/*
volatile int64_t number_of_calls_general_log;
volatile int64_t number_of_calls_general_error;
volatile int64_t number_of_calls_general_result;
volatile int64_t number_of_calls_general_status;
*/
/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
/*
volatile int64_t number_of_calls_connection_connect;
volatile int64_t number_of_calls_connection_disconnect;
volatile int64_t number_of_calls_connection_change_user;
*/
void number_of_calls_incr()
{
  number_of_calls++;
}

void number_of_calls_general_log_incr()
{
  number_of_calls_general_log++;
}

void number_of_calls_general_error_incr()
{
  number_of_calls_general_error++;
}

void number_of_calls_general_result_incr()
{
  number_of_calls_general_result++;
}

void number_of_calls_general_status_incr()
{
  number_of_calls_general_status++;
}

void number_of_calls_connection_connect_incr()
{
  number_of_calls_connection_connect++;
}

void number_of_calls_connection_disconnect_incr()
{
  number_of_calls_connection_disconnect++;
}

void number_of_calls_connection_change_user_incr()
{
  number_of_calls_connection_change_user++;
}

void number_of_calls_connection_pre_authenticate_incr()
{
  number_of_calls_connection_pre_authenticate++;
}

void number_of_calls_parse_preparse_incr()
{
  number_of_calls_parse_preparse++;
}

void number_of_calls_parse_postparse_incr()
{
  number_of_calls_parse_postparse++;
}

void number_of_calls_server_startup_incr()
{
  number_of_calls_server_startup++;
}

void number_of_calls_server_shutdown_incr()
{
//  printf("%d\n",number_of_calls_server_shutdown);
  number_of_calls_server_shutdown++;
}

void number_of_calls_command_start_incr()
{
  number_of_calls_command_start++;
}

void number_of_calls_command_end_incr()
{
  number_of_calls_command_end++;
}

void number_of_calls_query_start_incr()
{
  number_of_calls_query_start++;
}

void number_of_calls_query_nested_start_incr()
{
  number_of_calls_query_nested_start++;
}

void number_of_calls_query_status_end_incr()
{
  number_of_calls_query_status_end++;
}

void number_of_calls_query_nested_status_end_incr()
{
  number_of_calls_query_nested_status_end++;
}

void number_of_calls_table_access_insert_incr()
{
  number_of_calls_table_access_insert++;
}

void number_of_calls_table_access_delete_incr()
{
  number_of_calls_table_access_delete++;
}

void number_of_calls_table_access_update_incr()
{
  number_of_calls_table_access_update++;
}

void number_of_calls_table_access_read_incr()
{
  number_of_calls_table_access_read++;
}

void number_of_calls_global_variable_get_incr()
{
  number_of_calls_global_variable_get++;
}

void number_of_calls_global_variable_set_incr()
{
  number_of_calls_global_variable_set++;
}

void number_of_calls_authorization_user_incr()
{
  number_of_calls_authorization_user++;
}

void number_of_calls_authorization_db_incr()
{
  number_of_calls_authorization_db++;
}

void number_of_calls_authorization_table_incr()
{
  number_of_calls_authorization_table++;
}

void number_of_calls_authorization_column_incr()
{
  number_of_calls_authorization_column++;
}

void number_of_calls_authorization_procedure_incr()
{
  number_of_calls_authorization_procedure++;
}

void number_of_calls_authorization_proxy_incr()
{
  number_of_calls_authorization_proxy++;
}

void number_of_calls_stored_program_incr()
{
  number_of_calls_stored_program++;
}

/*被审计的事件统计*/
static volatile int64_t number_of_records; /* for SHOW STATUS, see below */
#define HTP_AUDIT_VAR_RECORD(x) static volatile int64_t number_of_records_ ## x;
/*
static volatile int64_t number_of_records_general_log;
static volatile int64_t number_of_records_general_error;
static volatile int64_t number_of_records_general_result;
static volatile int64_t number_of_records_general_status;
static volatile int64_t number_of_records_connection_connect;
static volatile int64_t number_of_records_connection_disconnect;
static volatile int64_t number_of_records_connection_change_user;
*/


/* Count MYSQL_AUDIT_GENERAL_CLASS event instances */
HTP_AUDIT_VAR_RECORD(general_log)
HTP_AUDIT_VAR_RECORD(general_error)
HTP_AUDIT_VAR_RECORD(general_result)
HTP_AUDIT_VAR_RECORD(general_status)

/* Count MYSQL_AUDIT_CONNECTION_CLASS event instances */
HTP_AUDIT_VAR_RECORD(connection_connect)
HTP_AUDIT_VAR_RECORD(connection_disconnect)
HTP_AUDIT_VAR_RECORD(connection_change_user)
HTP_AUDIT_VAR_RECORD(connection_pre_authenticate)
//HTP_AUDIT_VAR_RECORD(connection_pre_authenticate)

/* Count MYSQL_AUDIT_PARSE_CLASS event instances */
HTP_AUDIT_VAR_RECORD(parse_preparse)
HTP_AUDIT_VAR_RECORD(parse_postparse)

/* Count MYSQL_AUDIT_COMMAND_CLASS event instances */
HTP_AUDIT_VAR_RECORD(command_start)
HTP_AUDIT_VAR_RECORD(command_end)

/* Count MYSQL_AUDIT_AUTHORIZATION_CLASS event instances */
HTP_AUDIT_VAR_RECORD(authorization_user)
HTP_AUDIT_VAR_RECORD(authorization_db)
HTP_AUDIT_VAR_RECORD(authorization_table)
HTP_AUDIT_VAR_RECORD(authorization_column)
HTP_AUDIT_VAR_RECORD(authorization_procedure)
HTP_AUDIT_VAR_RECORD(authorization_proxy)

/* Count MYSQL_AUDIT_QUERY_CLASS event instances */
HTP_AUDIT_VAR_RECORD(query_start)
HTP_AUDIT_VAR_RECORD(query_nested_start)
HTP_AUDIT_VAR_RECORD(query_status_end)
HTP_AUDIT_VAR_RECORD(query_nested_status_end)

/* Count MYSQL_AUDIT_SERVER_STARTUP_CLASS event instances */
HTP_AUDIT_VAR_RECORD(server_startup)

/* Count MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS event instances */
HTP_AUDIT_VAR_RECORD(server_shutdown)

/* Count MYSQL_AUDIT_TABLE_ACCESS_CLASS event instances */
HTP_AUDIT_VAR_RECORD(table_access_insert)
HTP_AUDIT_VAR_RECORD(table_access_delete)
HTP_AUDIT_VAR_RECORD(table_access_update)
HTP_AUDIT_VAR_RECORD(table_access_read)

/* Count MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS event instances */
HTP_AUDIT_VAR_RECORD(global_variable_get)
HTP_AUDIT_VAR_RECORD(global_variable_set)

/* Count MYSQL_AUDIT_STORED_PROGRAM_CLASS event instances */
HTP_AUDIT_VAR_RECORD(stored_program)

void number_of_records_incr()
{
  number_of_records++;
}

void number_of_records_general_log_incr()
{
  number_of_records_general_log++;
}

void number_of_records_general_error_incr()
{
  number_of_records_general_error++;
}

void number_of_records_general_result_incr()
{
  number_of_records_general_result++;
}

void number_of_records_general_status_incr()
{
  number_of_records_general_status++;
}

void number_of_records_connection_connect_incr()
{
  number_of_records_connection_connect++;
}

void number_of_records_connection_disconnect_incr()
{
  number_of_records_connection_disconnect++;
}

void number_of_records_connection_change_user_incr()
{
  number_of_records_connection_change_user++;
}

void number_of_records_connection_pre_authenticate_incr()
{
  number_of_records_connection_pre_authenticate++;
}

void number_of_records_parse_preparse_incr()
{
  number_of_records_parse_preparse++;
}

void number_of_records_parse_postparse_incr()
{
  number_of_records_parse_postparse++;
}

void number_of_records_server_startup_incr()
{
  number_of_records_server_startup++;
}

void number_of_records_server_shutdown_incr()
{
  number_of_records_server_shutdown++;
}

void number_of_records_command_start_incr()
{
  number_of_records_command_start++;
}

void number_of_records_command_end_incr()
{
  number_of_records_command_end++;
}

void number_of_records_query_start_incr()
{
  number_of_records_query_start++;
}

void number_of_records_query_nested_start_incr()
{
  number_of_records_query_nested_start++;
}

void number_of_records_query_status_end_incr()
{
  number_of_records_query_status_end++;
}

void number_of_records_query_nested_status_end_incr()
{
  number_of_records_query_nested_status_end++;
}

void number_of_records_table_access_insert_incr()
{
  number_of_records_table_access_insert++;
}

void number_of_records_table_access_delete_incr()
{
  number_of_records_table_access_delete++;
}

void number_of_records_table_access_update_incr()
{
  number_of_records_table_access_update++;
}

void number_of_records_table_access_read_incr()
{
  number_of_records_table_access_read++;
}

void number_of_records_global_variable_get_incr()
{
  number_of_records_global_variable_get++;
}

void number_of_records_global_variable_set_incr()
{
  number_of_records_global_variable_set++;
}

void number_of_records_authorization_user_incr()
{
  number_of_records_authorization_user++;
}

void number_of_records_authorization_db_incr()
{
  number_of_records_authorization_db++;
}

void number_of_records_authorization_table_incr()
{
  number_of_records_authorization_table++;
}

void number_of_records_authorization_column_incr()
{
  number_of_records_authorization_column++;
}

void number_of_records_authorization_procedure_incr()
{
  number_of_records_authorization_procedure++;
}

void number_of_records_authorization_proxy_incr()
{
  number_of_records_authorization_proxy++;
}

void number_of_records_stored_program_incr()
{
  number_of_records_stored_program++;
}

/*
  Plugin status variables for SHOW STATUS
*/
struct st_mysql_show_var htp_audit_status[] =
    {
        {"Htp_audit_called",
         (char *) &number_of_calls,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_log_called",
         (char *) &number_of_calls_general_log,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_error_called",
         (char *) &number_of_calls_general_error,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_result_called",
         (char *) &number_of_calls_general_result,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_status_called",
         (char *) &number_of_calls_general_status,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_connect_called",
         (char *) &number_of_calls_connection_connect,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_disconnect_called",
         (char *) &number_of_calls_connection_disconnect,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_change_user_called",
         (char *) &number_of_calls_connection_change_user,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_pre_authenticate_called",
         (char *) &number_of_calls_connection_pre_authenticate,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_parse_preparse_called",
         (char *) &number_of_calls_parse_preparse,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_parse_postparse_called",
         (char *) &number_of_calls_parse_postparse,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_command_start_called",
         (char *) &number_of_calls_command_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_command_end_called",
         (char *) &number_of_calls_command_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_user_called",
         (char *) &number_of_calls_authorization_user,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_db_called",
         (char *) &number_of_calls_authorization_db,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_table_called",
         (char *) &number_of_calls_authorization_table,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_column_called",
         (char *) &number_of_calls_authorization_column,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_procedure_called",
         (char *) &number_of_calls_authorization_procedure,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_proxy_called",
         (char *) &number_of_calls_authorization_proxy,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_start_called",
         (char *) &number_of_calls_query_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_nested_start_called",
         (char *) &number_of_calls_query_nested_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_status_end_called",
         (char *) &number_of_calls_query_status_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_nested_status_end_called",
         (char *) &number_of_calls_query_nested_status_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_insert_called",
         (char *) &number_of_calls_table_access_insert,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_delete_called",
         (char *) &number_of_calls_table_access_delete,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_update_called",
         (char *) &number_of_calls_table_access_update,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_read_called",
         (char *) &number_of_calls_table_access_read,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_global_variable_get_called",
         (char *) &number_of_calls_global_variable_get,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_global_variable_set_called",
         (char *) &number_of_calls_global_variable_set,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_stored_program_called",
         (char *) &number_of_calls_stored_program,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_recorded",
         (char *) &number_of_records,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_log_recorded",
         (char *) &number_of_records_general_log,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_error_recorded",
         (char *) &number_of_records_general_error,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_result_recorded",
         (char *) &number_of_records_general_result,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_general_status_recorded",
         (char *) &number_of_records_general_status,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_connect_recorded",
         (char *) &number_of_records_connection_connect,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_disconnect_recorded",
         (char *) &number_of_records_connection_disconnect,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_change_user_recorded",
         (char *) &number_of_records_connection_change_user,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_connection_pre_authenticate_recorded",
         (char *) &number_of_records_connection_pre_authenticate,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_parse_preparse_recorded",
         (char *) &number_of_records_parse_preparse,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_parse_postparse_recorded",
         (char *) &number_of_records_parse_postparse,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_command_start_recorded",
         (char *) &number_of_records_command_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_command_end_recorded",
         (char *) &number_of_records_command_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_user_recorded",
         (char *) &number_of_records_authorization_user,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_db_recorded",
         (char *) &number_of_records_authorization_db,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_table_recorded",
         (char *) &number_of_records_authorization_table,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_column_recorded",
         (char *) &number_of_records_authorization_column,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_procedure_recorded",
         (char *) &number_of_records_authorization_procedure,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_authorization_proxy_recorded",
         (char *) &number_of_records_authorization_proxy,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_start_recorded",
         (char *) &number_of_records_query_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_nested_start_recorded",
         (char *) &number_of_records_query_nested_start,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_status_end_recorded",
         (char *) &number_of_records_query_status_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_query_nested_status_end_recorded",
         (char *) &number_of_records_query_nested_status_end,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_insert_recorded",
         (char *) &number_of_records_table_access_insert,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_delete_recorded",
         (char *) &number_of_records_table_access_delete,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_update_recorded",
         (char *) &number_of_records_table_access_update,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_table_access_read_recorded",
         (char *) &number_of_records_table_access_read,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_global_variable_get_recorded",
         (char *) &number_of_records_global_variable_get,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_global_variable_set_recorded",
         (char *) &number_of_records_global_variable_set,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {"Htp_audit_stored_program_recorded",
         (char *) &number_of_records_stored_program,
         SHOW_LONGLONG, SHOW_SCOPE_GLOBAL},
        {0, 0, SHOW_UNDEF, SHOW_SCOPE_GLOBAL}
    };

void htp_audit_init_status()
{
  number_of_calls = 0;
  number_of_calls_general_log = 0;
  number_of_calls_general_error = 0;
  number_of_calls_general_result = 0;
  number_of_calls_general_status = 0;
  number_of_calls_connection_connect = 0;
  number_of_calls_connection_disconnect = 0;
  number_of_calls_connection_change_user = 0;
  number_of_calls_parse_preparse = 0;
  number_of_calls_parse_postparse = 0;
  number_of_calls_command_start = 0;
  number_of_calls_command_end = 0;
  number_of_calls_authorization_user = 0;
  number_of_calls_authorization_db = 0;
  number_of_calls_authorization_table = 0;
  number_of_calls_authorization_column = 0;
  number_of_calls_authorization_procedure = 0;
  number_of_calls_authorization_proxy = 0;
  number_of_calls_query_start = 0;
  number_of_calls_query_nested_start = 0;
  number_of_calls_query_nested_start = 0;
  number_of_calls_query_status_end = 0;
  number_of_calls_query_nested_status_end = 0;
  number_of_calls_server_startup = 0;
  number_of_calls_server_shutdown = 0;
  number_of_calls_table_access_insert = 0;
  number_of_calls_table_access_update = 0;
  number_of_calls_table_access_delete = 0;
  number_of_calls_table_access_read = 0;
  number_of_calls_global_variable_get = 0;
  number_of_calls_global_variable_set = 0;
  number_of_calls_stored_program = 0;
  number_of_records = 0;
  number_of_records_general_log = 0;
  number_of_records_general_error = 0;
  number_of_records_general_result = 0;
  number_of_records_general_status = 0;
  number_of_records_connection_connect = 0;
  number_of_records_connection_disconnect = 0;
  number_of_records_connection_change_user = 0;
  number_of_records_parse_preparse = 0;
  number_of_records_parse_postparse = 0;
  number_of_records_command_start = 0;
  number_of_records_command_end = 0;
  number_of_records_authorization_user = 0;
  number_of_records_authorization_db = 0;
  number_of_records_authorization_table = 0;
  number_of_records_authorization_column = 0;
  number_of_records_authorization_procedure = 0;
  number_of_records_authorization_proxy = 0;
  number_of_records_query_start = 0;
  number_of_records_query_nested_start = 0;
  number_of_records_query_status_end = 0;
  number_of_records_query_nested_status_end = 0;
  number_of_records_server_startup = 0;
  number_of_records_server_shutdown = 0;
  number_of_records_table_access_insert = 0;
  number_of_records_table_access_update = 0;
  number_of_records_table_access_delete = 0;
  number_of_records_table_access_read = 0;
  number_of_records_global_variable_get = 0;
  number_of_records_global_variable_set = 0;
  number_of_records_stored_program = 0;

}

void htp_audit_deinit_status()
{
  //do nothing now
}

static rules2str_buffer_t rules_buffer;

static void htp_audit_add_rule_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save);    /*!< in: immediate result
							from check function */

static int htp_audit_add_rule_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
            variable */
    void *save,   /*!< out: immediate result
            for update function */
    struct st_mysql_value *value);  /*!< in: incoming string */


static void htp_audit_remove_rule_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save);    /*!< in: immediate result
							from check function */

static int htp_audit_remove_rule_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
            variable */
    void *save,   /*!< out: immediate result
            for update function */
    struct st_mysql_value *value);  /*!< in: incoming string */

static void htp_audit_set_enable_buffer_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save);    /*!< in: immediate result
							from check function */

static int htp_audit_flush_log_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
            variable */
    void *save,   /*!< out: immediate result
            for update function */
    struct st_mysql_value *value);  /*!< in: incoming string */

static void htp_audit_flush_log_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save);    /*!< in: immediate result
							from check function */
static int htp_audit_set_buffer_size_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
                variable */
    void *save,   /*!< out: immediate result
                      for update function */
    struct st_mysql_value *value);  /*!< in: incoming string */

static void htp_audit_set_buffer_size_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save);    /*!< in: immediate result
							from check function */




static MYSQL_SYSVAR_STR(log_file, log_file
, PLUGIN_VAR_READONLY
| PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit log file"
, NULL, NULL
, DEFAULT_LOG_FILE);

static MYSQL_SYSVAR_STR(error_log_file, error_log_file
, PLUGIN_VAR_READONLY
| PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit error log file"
, NULL, NULL
, DEFAULT_ERROR_LOG_FILE);

static MYSQL_SYSVAR_STR(rules, rules
, PLUGIN_VAR_READONLY
| PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit rules"
, NULL, NULL
, NULL);

static MYSQL_SYSVAR_STR(add_rule, add_rule
, PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit add new rule"
, htp_audit_add_rule_validate
, htp_audit_add_rule_update
, "");

static MYSQL_SYSVAR_STR(remove_rule, remove_rule
, PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit remove rule"
, htp_audit_remove_rule_validate
, htp_audit_remove_rule_update
, NULL);

static MYSQL_SYSVAR_BOOL(enable_buffer, enable_buffer
, PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "set whether use buffer to store audit record"
, NULL
, htp_audit_set_enable_buffer_update
, FALSE);

static MYSQL_SYSVAR_BOOL(flush_log, flush_log
, PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "set whether use buffer to store audit record"
, htp_audit_flush_log_validate
, htp_audit_flush_log_update
, FALSE);

static MYSQL_SYSVAR_INT(buffer_size, buffer_size
, PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "set audit log buffer size"
, htp_audit_set_buffer_size_validate
, htp_audit_set_buffer_size_update
, MIN_BUFFER_SIZE, MIN_BUFFER_SIZE
, MAX_BUFFER_SIZE, 0);

static MYSQL_SYSVAR_STR(version, version
, PLUGIN_VAR_READONLY
| PLUGIN_VAR_NOCMDOPT
| PLUGIN_VAR_NOCMDARG
, "Htp audit plugin version"
, NULL, NULL
, NULL);

struct st_mysql_sys_var *htp_audit_sys_var[] = {
    MYSQL_SYSVAR(log_file), MYSQL_SYSVAR(error_log_file), MYSQL_SYSVAR(rules), MYSQL_SYSVAR(add_rule),
    MYSQL_SYSVAR(remove_rule), MYSQL_SYSVAR(enable_buffer), MYSQL_SYSVAR(flush_log), MYSQL_SYSVAR(buffer_size),
    MYSQL_SYSVAR(version), 0
};

bool variable_initialized = false;

void htp_audit_init_variable()
{
  rules2str_buffer_init(&rules_buffer);

  htp_audit_rules_2_str(&rules_buffer);
  rules = rules_buffer.buffer;

  log_file = NULL;
  if (strlen(htp_audit_log_file) > 0)
    log_file = htp_audit_log_file;
  error_log_file = NULL;
  if (strlen(htp_audit_error_log_file) > 0)
    error_log_file = htp_audit_error_log_file;

  variable_initialized = true;
}

void htp_audit_deinit_variable()
{
  if (!variable_initialized)
    return;

  rules2str_buffer_deinit(&rules_buffer);
  variable_initialized = false;
}

/*************************************************************//**
Check if it is a valid add rule input. This function is registered as
a callback with MySQL.
@return	0 for valid input , 1 for invalid*/
static int htp_audit_add_rule_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
                      variable */
    void *save,   /*!< out: immediate result
                      for update function */
    struct st_mysql_value *value)  /*!< in: incoming string */
{
  const char *input;
  char buff[MAX_ADD_RULE_LENGTH + 1];
  int len = sizeof(buff);
  bool success = true;

  input = value->val_str(value, buff, &len);
  if (input == NULL)
    return (1);

  char *dup_str = strdup(input);
  if (dup_str == NULL)
    return (1);

  htp_audit_lock_filter_and_var();

  switch (0) {
    case 0:
      if (filters.size() >= MAX_FILTER_ITEMS) {
        success = false;
        break;
      }
      filter_item_t item;
      htp_audit_init_filter_item(&item);

      if (htp_audit_parse_filter(dup_str, &item) == -1)
      {
        success = false;
        break;
      }

      if (htp_audit_find_filter_by_name(item.name) != -1)
        success = false;

  }

  htp_audit_unlock_filter_and_var();

  *static_cast<const char **>(save) = input;
  free(dup_str);
  if (success)
    return (0);

  return (1);
}

static void htp_audit_add_rule_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save)    /*!< in: immediate result
							from check function */
{
  DBUG_ENTER("htp_audit_add_rule_update");
  const char *str = *(const char **) save;
  DBUG_PRINT("add rule update value", ("str: %s", str));
  char *dup_str = NULL;

  if (str == NULL)
    DBUG_VOID_RETURN;

  dup_str = strdup(str);
  if (dup_str == NULL)
    DBUG_VOID_RETURN;

  htp_audit_lock_filter_and_var();

  {
    if (add_rule != NULL) {
      free(add_rule);
    }

    filter_item_t item;
    htp_audit_init_filter_item(&item);

    htp_audit_parse_filter(dup_str, &item);
    htp_audit_add_filter(&item);

    add_rule = dup_str;
  }

  //返回设置后的值
  htp_audit_rules_2_str(&rules_buffer);
  rules = rules_buffer.buffer;
  *(const char **) var_ptr = add_rule;

  htp_audit_unlock_filter_and_var();

  DBUG_VOID_RETURN;
}

/*************************************************************//**
Check if it is a valid remove rule input. This function is registered as
a callback with MySQL.
@return	0 for valid input , 1 for invalid*/
static int htp_audit_remove_rule_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
                      variable */
    void *save,   /*!< out: immediate result
                      for update function */
    struct st_mysql_value *value)  /*!< in: incoming string */
{
  const char *input;
  char buff[MAX_ADD_RULE_LENGTH + 1];
  int len = sizeof(buff);
  bool success = true;

  input = value->val_str(value, buff, &len);
  if (input == NULL)
    return (1);

  htp_audit_lock_filter_and_var();
  {
    remove_parse_t parse;
    remove_parse_init(&parse);
    htp_audit_parse_remove_input(input, &parse);

    if (htp_audit_remove_rule_check_exist(&parse) == -1)
      success = false;

    *static_cast<const char **>(save) = input;
  }
  htp_audit_unlock_filter_and_var();

  if (success)
    return (0);

  return (1);
}

static void htp_audit_remove_rule_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save)    /*!< in: immediate result
							from check function */
{
  DBUG_ENTER("htp_audit_remove_rule_update");
  const char *str = *(const char **) save;
  DBUG_PRINT("add rule update value", ("str: %s", str));

  if (str == NULL)
    DBUG_VOID_RETURN;

  char *dup_str = strdup(str);
  if (dup_str == NULL)
    DBUG_VOID_RETURN;

  htp_audit_lock_filter_and_var();

  {
    if (remove_rule != NULL) {
      free(remove_rule);
    }
    remove_rule = dup_str;
    remove_parse_t parse;

    remove_parse_init(&parse);
    htp_audit_parse_remove_input(str, &parse);
    htp_audit_remove_filter(&parse);
  }

  //返回设置后的值
  htp_audit_rules_2_str(&rules_buffer);
  rules = rules_buffer.buffer;
  *(const char **) var_ptr = remove_rule;
  htp_audit_unlock_filter_and_var();
  //*(const char**)var_ptr= “hello update add rule”;
  DBUG_VOID_RETURN;
}

static void htp_audit_set_enable_buffer_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save)    /*!< in: immediate result
							from check function */
{
  DBUG_ENTER("htp_audit_set_enable_buffer_update");
  my_bool nvalue = (*(static_cast<const my_bool *>(save)) != 0);

  if (nvalue == enable_buffer)
    DBUG_VOID_RETURN;

  if (nvalue == FALSE) {
    Logger::GetLogger()->EnableBuffer(false);
    Logger::GetELogger()->EnableBuffer(false);
  }
  else {
    Logger::GetLogger()->EnableBuffer(true);
    Logger::GetELogger()->EnableBuffer(true);
  }

  enable_buffer = nvalue;

  DBUG_VOID_RETURN;
}

static int htp_audit_flush_log_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
                      variable */
    void *save,   /*!< out: immediate result
                      for update function */
    struct st_mysql_value *value)  /*!< in: incoming string */
{
  DBUG_ENTER("htp_audit_flush_log_validate");
  long long tmp;

  value->val_int(value, &tmp);
  if (tmp) {
    int ret = Logger::FlushNew();
    if (ret) {
      //    *static_cast<long long*>(save) = TRUE;
      //    *(my_bool*) save = TRUE;
      DBUG_RETURN(ret);
    }
    else {
      //*static_cast<long long*>(save) = FALSE;
      //    *(my_bool*) save = FALSE;
      DBUG_RETURN(0);
    }
  }

  DBUG_RETURN(1);
}

static void htp_audit_flush_log_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save)    /*!< in: immediate result
							from check function */
{
  DBUG_ENTER("htp_audit_flush_log_update");

  //  my_bool flush = *(my_bool*) save;

  DBUG_VOID_RETURN;
}

static int htp_audit_set_buffer_size_validate(
    /*=============================*/
    THD *thd,  /*!< in: thread handle */
    struct st_mysql_sys_var *var,  /*!< in: pointer to system
                      variable */
    void *save,   /*!< out: immediate result
                      for update function */
    struct st_mysql_value *value)  /*!< in: incoming string */
{
  DBUG_ENTER("htp_audit_flush_log_validate");

  long long tmp;
  value->val_int(value, &tmp);

  int setted_value = (int) tmp;
  if (setted_value < MIN_BUFFER_SIZE)
    DBUG_RETURN(1);
  if (setted_value > MAX_BUFFER_SIZE)
    DBUG_RETURN(1);

  *static_cast<ulonglong *>(save) = setted_value;

  DBUG_RETURN(0);
}

static void htp_audit_set_buffer_size_update(
    THD *thd,    /*!< in: thread handle */
    struct st_mysql_sys_var *var,    /*!< in: pointer to
							system variable */
    void *var_ptr,  /*!< out: where the
							formal string goes */
    const void *save)    /*!< in: immediate result
							from check function */
{
  DBUG_ENTER("htp_audit_set_buffer_size_update");

  int setted_value = *((int *) save);
  if (setted_value == buffer_size)
    DBUG_VOID_RETURN;

  Logger::SetBufferSize(setted_value);
  buffer_size = setted_value;

  DBUG_VOID_RETURN;
}

