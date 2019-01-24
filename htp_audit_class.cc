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
//#include <my_global.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql/sql_plugin.h>
//#include "htp_audit.h"
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "sql/log.h"
#include "htp_audit_vars.h"
#include "htp_audit_filter.h"

using namespace std;
/* 审计事件处理 */

/*解析general传入的user串*/
static void htp_audit_general_event_get_user(const char *general_user, char *user)
{
  int len = strlen(general_user);
  int user_len = 0;
  for (int i = 0; i < len; i++) {
    if (general_user[i] == '[')
      break;

    user[user_len] = general_user[i];
    user_len++;
  }
  user[user_len] = 0;
}

static int htp_audit_process_general_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_general *event_general =
      (const struct mysql_event_general *) event;

  event_info_t info;
  char user[256];
  htp_audit_general_event_get_user(event_general->general_user.str, user);
  info.ip = event_general->general_ip.str;
  info.user = user;
  info.host = event_general->general_host.str;
  info.main_class = MYSQL_AUDIT_GENERAL_CLASS;
  info.sub_class = event_general->event_subclass;
  info.command = event_general->general_command.str;
  info.query = event_general->general_query.str;
  info.sql_command = event_general->general_sql_command.str;
  //统计调用次数
  switch (event_general->event_subclass) {
    case MYSQL_AUDIT_GENERAL_LOG:
      number_of_calls_general_log_incr();
      break;
    case MYSQL_AUDIT_GENERAL_ERROR:
      number_of_calls_general_error_incr();
      break;
    case MYSQL_AUDIT_GENERAL_RESULT:
      number_of_calls_general_result_incr();
      break;
    case MYSQL_AUDIT_GENERAL_STATUS:
      number_of_calls_general_status_incr();
      break;
    default:
      break;
  }

  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }

  number_of_records_incr();
  //进行审计
  switch (event_general->event_subclass) {
    case MYSQL_AUDIT_GENERAL_LOG:
      number_of_records_general_log_incr();
      audit_general_log(event_general);
      break;
    case MYSQL_AUDIT_GENERAL_ERROR:
      number_of_records_general_error_incr();
      audit_general_error(event_general);
      break;
    case MYSQL_AUDIT_GENERAL_RESULT:
      number_of_records_general_result_incr();
      audit_general_result(event_general);
      break;
    case MYSQL_AUDIT_GENERAL_STATUS:
      number_of_records_general_status_incr();
      audit_general_status(event_general);
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_connection_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_connection *event_connection =
      (const struct mysql_event_connection *) event;

  event_info_t info;
  info.ip = event_connection->ip.str;
  info.user = event_connection->user.str;
  info.host = event_connection->host.str;
  info.main_class = MYSQL_AUDIT_CONNECTION_CLASS;
  info.sub_class = event_connection->event_subclass;

  switch (event_connection->event_subclass) {
    case MYSQL_AUDIT_CONNECTION_CONNECT:
      number_of_calls_connection_connect_incr();
      break;
    case MYSQL_AUDIT_CONNECTION_DISCONNECT:
      number_of_calls_connection_disconnect_incr();
      break;
    case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
      number_of_calls_connection_change_user_incr();
      break;
    case MYSQL_AUDIT_CONNECTION_PRE_AUTHENTICATE:
      number_of_calls_connection_pre_authenticate_incr();
      break;
    default:
      break;
  }

  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }

  number_of_records_incr();
  switch (event_connection->event_subclass) {
    case MYSQL_AUDIT_CONNECTION_CONNECT:
      number_of_records_connection_connect_incr();
      audit_connection_connect(event_connection);
      break;
    case MYSQL_AUDIT_CONNECTION_DISCONNECT:
      number_of_records_connection_disconnect_incr();
      audit_connection_disconnect(event_connection);
      break;
    case MYSQL_AUDIT_CONNECTION_CHANGE_USER:
      number_of_records_connection_change_user_incr();
      audit_connection_change_user(event_connection);
      break;
    case MYSQL_AUDIT_CONNECTION_PRE_AUTHENTICATE:
      number_of_records_connection_pre_authenticate_incr();
      audit_connection_pre_authenticate(event_connection);
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_parse_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_parse
      *event_parse = (const struct mysql_event_parse *) event;
  event_info_t info;
  info.main_class = MYSQL_AUDIT_PARSE_CLASS;
  info.sub_class = event_parse->event_subclass;
  info.query = event_parse->query.str;
  switch (event_parse->event_subclass) {
    case MYSQL_AUDIT_PARSE_PREPARSE:
      number_of_calls_parse_preparse_incr();
      break;
    case MYSQL_AUDIT_PARSE_POSTPARSE:
      number_of_calls_parse_postparse_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }
  number_of_records_incr();
  switch (event_parse->event_subclass) {
    case MYSQL_AUDIT_PARSE_PREPARSE:
      audit_parse_preparse(event_parse);
      number_of_records_parse_preparse_incr();
      break;
    case MYSQL_AUDIT_PARSE_POSTPARSE:
      audit_parse_postparse(event_parse);
      number_of_records_parse_postparse_incr();
      break;
    default:
      break;
  }
  return 0;
}

static int
htp_audit_process_auth_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_authorization *event_grant =
      (const struct mysql_event_authorization *) event;
/*
  buffer_data= sprintf(buffer, "db=\"%s\" table=\"%s\" object=\"%s\" "
       "requested=\"0x%08x\" granted=\"0x%08x\"",
       event_grant->database.str ? event_grant->database.str : "<NULL>",
       event_grant->table.str ? event_grant->table.str : "<NULL>",
       event_grant->object.str ? event_grant->object.str : "<NULL>",
       event_grant->requested_privilege,
       event_grant->granted_privilege);
*/
  event_info_t info;
  info.main_class = MYSQL_AUDIT_AUTHORIZATION_CLASS;
  info.sub_class = event_grant->event_subclass;
  info.query = event_grant->query.str;
  info.database = event_grant->database.str;
  info.table = event_grant->table.str;

  switch (event_grant->event_subclass) {
    case MYSQL_AUDIT_AUTHORIZATION_USER:
      audit_authorization_user(event_grant);
      number_of_calls_authorization_user_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_DB:
      audit_authorization_db(event_grant);
      number_of_calls_authorization_db_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_TABLE:
      audit_authorization_table(event_grant);
      number_of_calls_authorization_table_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_COLUMN:
      audit_authorization_column(event_grant);
      number_of_calls_authorization_column_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_PROCEDURE:
      audit_authorization_procedure(event_grant);
      number_of_calls_authorization_procedure_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_PROXY:
      audit_authorization_proxy(event_grant);
      number_of_calls_authorization_proxy_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }

  switch (event_grant->event_subclass) {
    case MYSQL_AUDIT_AUTHORIZATION_USER:
      audit_authorization_user(event_grant);
      number_of_records_authorization_user_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_DB:
      audit_authorization_db(event_grant);
      number_of_records_authorization_db_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_TABLE:
      audit_authorization_table(event_grant);
      number_of_records_authorization_table_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_COLUMN:
      audit_authorization_column(event_grant);
      number_of_records_authorization_column_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_PROCEDURE:
      audit_authorization_procedure(event_grant);
      number_of_records_authorization_procedure_incr();
      break;
    case MYSQL_AUDIT_AUTHORIZATION_PROXY:
      audit_authorization_proxy(event_grant);
      number_of_records_authorization_proxy_incr();
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_startup_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  //const struct mysql_event_server_startup *event_startup =
  //    (const struct mysql_event_server_startup *) event;
  //audit_server_startup_startup(event_startup);
  number_of_calls_server_startup_incr();
  number_of_records_server_startup_incr();


  // mysql 8.0 编译
  event_class = event_class;
  event = event;


  return 0;
}

static int
htp_audit_process_shutdown_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_server_shutdown *event_shutdown =
      (const struct mysql_event_server_shutdown *) event;

  event_info_t info;
  info.main_class = MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS;
  info.sub_class = event_shutdown->event_subclass;
  number_of_calls_server_shutdown_incr();

  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }
  number_of_records_server_shutdown_incr();
  audit_server_shutdown_shutdown(event_shutdown);
  return 0;
}

static int
htp_audit_process_stored_program_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_stored_program *event_stored_program =
      (const struct mysql_event_stored_program *) event;
  event_info_t info;
  info.main_class = MYSQL_AUDIT_STORED_PROGRAM_CLASS;
  info.sub_class = event_stored_program->event_subclass;
  info.query = event_stored_program->query.str;
  info.database = event_stored_program->database.str;
  info.name = event_stored_program->name.str;

  number_of_calls_stored_program_incr();
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }
  audit_stored_program_event(event_stored_program);
  number_of_records_stored_program_incr();
  return 0;
}

static int htp_audit_process_command_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  /* const struct mysql_event_server_shutdown *event_startup=
   (const struct mysql_event_server_shutdown *) event; */
  const struct mysql_event_command *event_command =
      (const struct mysql_event_command *) event;

  //debug test for deinit
  //  sleep(10);
  event_info_t info;
  info.main_class = MYSQL_AUDIT_COMMAND_CLASS;
  info.sub_class = event_command->event_subclass;

  switch (event_command->event_subclass) {
    case MYSQL_AUDIT_COMMAND_START:
      number_of_calls_command_start_incr();
      break;
    case MYSQL_AUDIT_COMMAND_END:
      number_of_calls_command_end_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }

  switch (event_command->event_subclass) {
    case MYSQL_AUDIT_COMMAND_START:
      audit_command_start(event_command);
      number_of_records_command_start_incr();
      break;
    case MYSQL_AUDIT_COMMAND_END:
      audit_command_end(event_command);
      number_of_records_command_end_incr();
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_query_event(
    MYSQL_THD thd __attribute__((unused)), unsigned int event_class, const void *event)
{
  const struct mysql_event_query *event_query =
      (const struct mysql_event_query *) event;

  event_info_t info;
  info.main_class = MYSQL_AUDIT_QUERY_CLASS;
  info.sub_class = event_query->event_subclass;

  switch (event_query->event_subclass) {
    case MYSQL_AUDIT_QUERY_START:
      number_of_calls_query_start_incr();
      break;
    case MYSQL_AUDIT_QUERY_NESTED_START:
      number_of_calls_query_nested_start_incr();
      break;
    case MYSQL_AUDIT_QUERY_STATUS_END:
      number_of_calls_query_status_end_incr();
      break;
    case MYSQL_AUDIT_QUERY_NESTED_STATUS_END:
      number_of_calls_query_nested_status_end_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }

  switch (event_query->event_subclass) {
    case MYSQL_AUDIT_QUERY_START:
      audit_query_start(event_query);
      number_of_records_query_start_incr();
      break;
    case MYSQL_AUDIT_QUERY_NESTED_START:
      audit_query_nested_start(event_query);
      number_of_records_query_nested_start_incr();
      break;
    case MYSQL_AUDIT_QUERY_STATUS_END:
      audit_query_status_end(event_query);
      number_of_records_query_status_end_incr();
      break;
    case MYSQL_AUDIT_QUERY_NESTED_STATUS_END:
      audit_query_nested_status_end(event_query);
      number_of_records_query_nested_status_end_incr();
      break;
    default:
      break;
  }

  return 0;
}

static int htp_audit_process_table_access_event(MYSQL_THD thd __attribute__((unused)),
                                                unsigned int event_class,
                                                const void *event)
{
  const struct mysql_event_table_access *event_table =
      (const struct mysql_event_table_access *) event;

  event_info_t info;
  info.main_class = MYSQL_AUDIT_TABLE_ACCESS_CLASS;
  info.sub_class = event_table->event_subclass;

  switch (event_table->event_subclass) {
    case MYSQL_AUDIT_TABLE_ACCESS_INSERT:
      number_of_calls_table_access_insert_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_DELETE:
      number_of_calls_table_access_delete_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_UPDATE:
      number_of_calls_table_access_update_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_READ:
      number_of_calls_table_access_read_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }
  switch (event_table->event_subclass) {
    case MYSQL_AUDIT_TABLE_ACCESS_INSERT:
      audit_table_access_insert(event_table);
      number_of_records_table_access_insert_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_DELETE:
      audit_table_access_delete(event_table);
      number_of_records_table_access_delete_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_UPDATE:
      audit_table_access_update(event_table);
      number_of_records_table_access_update_incr();
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_READ:
      audit_table_access_read(event_table);
      number_of_records_table_access_read_incr();
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_variable_event(MYSQL_THD thd __attribute__((unused)),
                                            unsigned int event_class,
                                            const void *event)
{
  const struct mysql_event_global_variable *event_gvar =
      (const struct mysql_event_global_variable *) event;

  /* Copy the variable content into the buffer. We do not guarantee that the
   variable value will fit into buffer. The buffer should be large enough
   to be used for the test purposes. */
  /*  buffer_data= sprintf(buffer, "name=\"%.*s\"",
    MY_MIN((int) event_gvar->variable_name.length,
    (int) (sizeof(buffer) - 8)),
    event_gvar->variable_name.str);

    buffer_data+= sprintf(buffer + buffer_data, " value=\"%.*s\"",
    MY_MIN((int) event_gvar->variable_value.length,
    (int) (sizeof(buffer) - 16)),
    event_gvar->variable_value.str);
    buffer[buffer_data]= '\0';*/
  event_info_t info;
  info.main_class = MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS;
  info.sub_class = event_gvar->event_subclass;

  switch (event_gvar->event_subclass) {
    case MYSQL_AUDIT_GLOBAL_VARIABLE_GET:
      number_of_calls_global_variable_get_incr();
      break;
    case MYSQL_AUDIT_GLOBAL_VARIABLE_SET:
      number_of_calls_global_variable_set_incr();
      break;
    default:
      break;
  }
  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT) {
    return 0;
  }
  switch (event_gvar->event_subclass) {
    case MYSQL_AUDIT_GLOBAL_VARIABLE_GET:

      audit_global_variable_get(event_gvar);
      number_of_records_global_variable_get_incr();
      break;
    case MYSQL_AUDIT_GLOBAL_VARIABLE_SET:
      audit_global_variable_set(event_gvar);
      number_of_records_global_variable_set_incr();
      break;
    default:
      break;
  }
  return 0;
}

static int htp_audit_process_authentication_event(MYSQL_THD thd __attribute__((unused)),
                                                  unsigned int event_class,
                                                  const void *event)
{
  const struct mysql_event_authentication *event_auth =
      (const struct mysql_event_authentication *) event;

  event_info_t info;
  info.main_class = MYSQL_AUDIT_AUTHENTICATION_CLASS;
  info.sub_class = event_auth->event_subclass;

  switch (event_auth->event_subclass) 
  {
    case MYSQL_AUDIT_AUTHENTICATION_FLUSH:
      number_of_calls_authentication_flush_incr();
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_CREATE:
      number_of_calls_authentication_authid_create_incr();
      break;
    case MYSQL_AUDIT_AUTHENTICATION_CREDENTIAL_CHANGE:
      number_of_calls_authentication_credential_change_incr();
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_RENAME:
      number_of_calls_authentication_authid_rename_incr();
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_DROP:
      number_of_calls_authentication_authid_drop_incr();
      break;
    default:
      break;
  }

  if (htp_audit_filter_event(&info, event_class) == NOT_AUDIT_EVENT)
  {
    return 0;
  }

  switch (event_auth->event_subclass)
  {
    case MYSQL_AUDIT_AUTHENTICATION_FLUSH:
      number_of_records_authentication_flush_incr();
      audit_authentication_flush(event_auth);
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_CREATE:
      number_of_records_authentication_authid_create_incr();
      audit_authentication_authid_create(event_auth);
      // todo
      break;
    case MYSQL_AUDIT_AUTHENTICATION_CREDENTIAL_CHANGE:
      number_of_records_authentication_credential_change_incr();
      audit_authentication_credential_change(event_auth);
      // todo
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_RENAME:
      number_of_records_authentication_authid_rename_incr();
      audit_authentication_authid_rename(event_auth);
      // todo
      break;
    case MYSQL_AUDIT_AUTHENTICATION_AUTHID_DROP:
      number_of_records_authentication_authid_drop_incr();
      audit_authentication_authid_drop(event_auth);
      // todo
      break;
    default:
      break;
  }
  return 0;
}

void htp_audit_process_event(MYSQL_THD thd __attribute__((unused)),
                             unsigned int event_class,
                             const void *event)
{
  switch (event_class) {
    case MYSQL_AUDIT_GENERAL_CLASS:
      htp_audit_process_general_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_CONNECTION_CLASS:
      htp_audit_process_connection_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_PARSE_CLASS:
      htp_audit_process_parse_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_AUTHORIZATION_CLASS:
      htp_audit_process_auth_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_TABLE_ACCESS_CLASS:
      htp_audit_process_table_access_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_GLOBAL_VARIABLE_CLASS:
      htp_audit_process_variable_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_SERVER_STARTUP_CLASS:
      htp_audit_process_startup_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_SERVER_SHUTDOWN_CLASS:
      htp_audit_process_shutdown_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_COMMAND_CLASS:
      htp_audit_process_command_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_QUERY_CLASS:
      htp_audit_process_query_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_STORED_PROGRAM_CLASS:
      htp_audit_process_stored_program_event(thd, event_class, event);
      break;
    case MYSQL_AUDIT_AUTHENTICATION_CLASS:
      htp_audit_process_authentication_event(thd, event_class, event);
      break;
    default:
      DBUG_ASSERT(FALSE);
  }
}
