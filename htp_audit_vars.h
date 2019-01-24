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

//
// Created by gqhao on 9/30/18.
//

#ifndef MYSQL_HTP_AUDIT_VARS_H
#define MYSQL_HTP_AUDIT_VARS_H
//#include"htp_audit_filter.h"
//#include"htp_audit.h"

#define MAX_ADD_RULE_LENGTH 1024
#define DEFAULT_LOG_FILE "htp_audit.log"
#define DEFAULT_ERROR_LOG_FILE "htp_audit_error.log"

#define HTP_AUDIT_CONFIG_MAX_FILE_NAME 1024
/* filter to string */
#define RULE_ITEM_BUFFER_LEN (32 * 1024)
#define RULES2STR_BUFFER_LEN (32 * 1024)

struct rules2str_buffer_struct
{
  char *buffer;     //buffer指针
  char buffer_inner[RULES2STR_BUFFER_LEN];   //初始缓冲区
  int buffer_size;    //buffer的长度
  int occupied_bytes;   //使用的字节数
};
typedef struct rules2str_buffer_struct rules2str_buffer_t;

void number_of_calls_incr();

void number_of_calls_general_log_incr();

void number_of_calls_general_error_incr();

void number_of_calls_general_result_incr();

void number_of_calls_general_status_incr();

void number_of_calls_connection_connect_incr();

void number_of_calls_connection_disconnect_incr();

void number_of_calls_connection_change_user_incr();

void number_of_calls_connection_pre_authenticate_incr();

void number_of_calls_parse_preparse_incr();

void number_of_calls_parse_postparse_incr();

void number_of_calls_server_startup_incr();

void number_of_calls_server_shutdown_incr();

void number_of_calls_command_start_incr();

void number_of_calls_command_end_incr();

void number_of_calls_query_start_incr();

void number_of_calls_query_nested_start_incr();

void number_of_calls_query_status_end_incr();

void number_of_calls_query_nested_status_end_incr();

void number_of_calls_table_access_insert_incr();

void number_of_calls_table_access_delete_incr();

void number_of_calls_table_access_update_incr();

void number_of_calls_table_access_read_incr();

void number_of_calls_global_variable_get_incr();

void number_of_calls_global_variable_set_incr();

void number_of_calls_authorization_user_incr();

void number_of_calls_authorization_db_incr();

void number_of_calls_authorization_table_incr();

void number_of_calls_authorization_column_incr();

void number_of_calls_authorization_procedure_incr();

void number_of_calls_authorization_proxy_incr();

void number_of_calls_stored_program_incr();

void number_of_calls_authentication_flush_incr();

void number_of_calls_authentication_authid_create_incr();

void number_of_calls_authentication_credential_change_incr();

void number_of_calls_authentication_authid_rename_incr();

void number_of_calls_authentication_authid_drop_incr();

void number_of_records_incr();

void number_of_records_general_log_incr();

void number_of_records_general_error_incr();

void number_of_records_general_result_incr();

void number_of_records_general_status_incr();

void number_of_records_connection_connect_incr();

void number_of_records_connection_disconnect_incr();

void number_of_records_connection_change_user_incr();

void number_of_records_connection_pre_authenticate_incr();

void number_of_records_parse_preparse_incr();

void number_of_records_parse_postparse_incr();

void number_of_records_server_startup_incr();

void number_of_records_server_shutdown_incr();

void number_of_records_command_start_incr();

void number_of_records_command_end_incr();

void number_of_records_query_start_incr();

void number_of_records_query_nested_start_incr();

void number_of_records_query_status_end_incr();

void number_of_records_query_nested_status_end_incr();

void number_of_records_table_access_insert_incr();

void number_of_records_table_access_delete_incr();

void number_of_records_table_access_update_incr();

void number_of_records_table_access_read_incr();

void number_of_records_global_variable_get_incr();

void number_of_records_global_variable_set_incr();

void number_of_records_authorization_user_incr();

void number_of_records_authorization_db_incr();

void number_of_records_authorization_table_incr();

void number_of_records_authorization_column_incr();

void number_of_records_authorization_procedure_incr();

void number_of_records_authorization_proxy_incr();

void number_of_records_stored_program_incr();

void number_of_records_authentication_flush_incr();

void number_of_records_authentication_authid_create_incr();

void number_of_records_authentication_credential_change_incr();

void number_of_records_authentication_authid_rename_incr();

void number_of_records_authentication_authid_drop_incr();

void htp_audit_deinit_status();

void htp_audit_deinit_variable();

void htp_audit_init_status();

void htp_audit_init_variable();



#endif //MYSQL_HTP_AUDIT_VARS_H
