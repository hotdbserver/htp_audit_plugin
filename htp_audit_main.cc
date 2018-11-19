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
#include <list>
#include <ctype.h>
#include <string>
#include "config.h"
#include "log.h"
#include "htp_audit_filter.h"
#include "htp_audit_vars.h"
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>
#include <sql_plugin.h>

extern char htp_audit_log_file[];
extern char htp_audit_error_log_file[];
extern char *log_file;
extern char *error_log_file;
extern my_bool enable_buffer;
extern struct st_mysql_show_var htp_audit_status[];
extern struct st_mysql_sys_var *htp_audit_sys_var[];

/* 配置读入，并根据配置构造运行环境 */
static int htp_audit_rules_from_config(config_group_t *group)
{
  config_item_t *config_item;
  filter_item_t filter_item;

  htp_audit_init_filter_item(&filter_item);

  //从group中构造filter item的内容
  config_item = group->items;
  while (config_item != NULL) {
    if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_NAME) == 0) {
      if (filter_item.name_setted == true) {
        //同一组中相同属性被多次指定
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate name setting in group %d",
                       group->number);
        return -1;
      }

      if (htp_audit_find_filter_by_name(config_item->value) >= 0) {
        //配置文件中出现重名的配置项
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "group %s already defined.", config_item->value);
        return -1;
      }

      strcpy(filter_item.name, config_item->value);
      filter_item.name_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_HOST) == 0) {
      if (filter_item.host_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate host setting in group %d",
                       group->number);
        return -1;
      }

      strcpy(filter_item.host, config_item->value);
      filter_item.host_length = strlen(config_item->value);
      if (htp_audit_check_value_valid(
          filter_item.host, filter_item.host_length)) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "invalid host setting value in group %d",
                       group->number);
        return -1;
      }

      filter_item.host_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_USER) == 0) {
      if (filter_item.user_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate user setting in group %d",
                       group->number);
        return -1;
      }

      strcpy(filter_item.user, config_item->value);
      filter_item.user_length = strlen(config_item->value);
      if (htp_audit_check_value_valid(
          filter_item.user, filter_item.user_length)) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "invalid user setting value in group %d",
                       group->number);
        return -1;
      }

      filter_item.user_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_EVENT) == 0) {
      if (filter_item.event_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate event setting in group %d",
                       group->number);
        return -1;
      }

      int r = 0;
      int event_len = strlen(config_item->value);
      r = htp_audit_parse_event(config_item->value, event_len, &filter_item);
      if (r) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "invalid event setting value in group %d",
                       group->number);
        return -1;
      }

      filter_item.event_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_CMD) == 0) {
      if (filter_item.command_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate command setting in group %d",
                       group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_COMMAND_BUFFER_SIZE) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "too long value for command setting");
        return -1;
      }
      strncpy(filter_item.command, config_item->value, config_item->value_len);
      if (strcasecmp(filter_item.command,"query") !=0 && strcasecmp(filter_item.command,"execute") !=0)
      {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "command can only be setted to query or execute",
                       group->number);
        return -1;
      }
      filter_item.command[config_item->value_len] = 0;
      filter_item.command_length = config_item->value_len;
      filter_item.command_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_SQL_CMD) == 0) {
      if (filter_item.sql_command_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate sql_command setting in group %d",
                       group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_SQL_COMMAND_BUFFER_SIZE) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "too long value for sql_command setting in group %d",
                       group->number);
        return -1;
      }
      strncpy(filter_item.sql_command, config_item->value, config_item->value_len);
      filter_item.sql_command[config_item->value_len] = 0;
      filter_item.sql_command_length = config_item->value_len;
      filter_item.sql_command_setted = true;
    }
    else if (strcasecmp(config_item->key, HTP_AUDIT_RULE_KEY_SQL_KEYWORD) == 0) {
      if (filter_item.sql_keyword_setted == true) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "duplicate sql_keyword setting in group %d",
                       group->number);
        return -1;
      }

      if (config_item->value_len >= MAX_FILTER_SQL_KEYWORD_BUFFER_SIZE) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "too long value for sql_keyword setting in group %d",
                       group->number);
        return -1;
      }
      strncpy(filter_item.sql_keyword, config_item->value, config_item->value_len);
      filter_item.sql_keyword[config_item->value_len] = 0;
      filter_item.sql_keyword_length = config_item->value_len;
      filter_item.sql_keyword_setted = true;
    }
    else {
      //不可识别的内容
      string err_msg = "unknow settings : ";
      err_msg += config_item->key;
      const char *c_err_msg = err_msg.c_str();
      htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                     c_err_msg);
      return -1;
    }

    config_item = (config_item_t *) config_item->next;
  }
  //进行rule filter item的检查和补充
  int r = htp_audit_reorg_filter_item(&filter_item);
  if (r != 0)
    return r;

  //将filter加入
  htp_audit_add_filter(&filter_item);

  return (0);
}

static int htp_audit_general_from_config(config_group_t *group)
{
  config_item_t *item;
  item = group->items;
  while (item != NULL) {
    if (strcasecmp(item->key, HTP_AUDIT_GENERAL_SECTION_AUDIT_FILE) == 0) {
      strcpy(htp_audit_log_file, item->value);
    }
    else if (strcasecmp
        (item->key, HTP_AUDIT_GENERAL_SECTION_AUDIT_ERROR_FILE) == 0) {
      strcpy(htp_audit_error_log_file, item->value);
    }
    else if (strcasecmp
        (item->key, HTP_AUDIT_GENERAL_SECTION_AUDIT_ENABLE_BUFFER) == 0) {
      if (strcasecmp(item->value, "1") == 0
          || strcasecmp(item->value, "on") == 0) {
        enable_buffer = TRUE;
      }
      else if (strcasecmp(item->value, "off") == 0
          || strcasecmp(item->value, "0") == 0) {
        enable_buffer = FALSE;
      }
      else {
      }
    }
    else {
      //不可识别的配置内容
      return 1;
    }

    item = (config_item_t *) item->next;
  }
  return 0;
}

static int htp_audit_init_env_from_config(config_t *config)
{
  config_group_t *group;

  htp_audit_log_file[0] = 0;
  htp_audit_error_log_file[0] = 0;

  group = config->groups;
  while (group != NULL) {
    if (strcasecmp(group->name, HTP_AUDIT_RULE_GROUP_NAME) == 0) {
      if (htp_audit_rules_from_config(group)) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                       "group %d error", group->number);
        return -1;
      }
    }
    else if (strcasecmp(group->name, HTP_AUDIT_GENERAL_GROUP_NAME) == 0) {
      if (htp_audit_general_from_config(group))
        return -1;
    }
    else {
      htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR,
                     "unknown group name : %s", group->name);
      return -1;
    }

    group = (config_group_t *) group->next;
  }

  return (0);
}

static int htp_audit_read_config_and_init_env()
{
  config_t *config = NULL;
  char config_file[256];
  int ret;

  sprintf(config_file, "%s%s", opt_plugin_dir, HTP_AUDIT_CONFIG_FILE);

  config = config_read(config_file);
  if (config == NULL)
    return (0);

  ret = htp_audit_init_env_from_config(config);

  config_destroy(config);

  return (ret);
}

/** probe quiting condition */
volatile bool quiting = false;

bool probe_quiting_condition()
{
  quiting = true;
  return true;
}

/* 插件接口 */
static bool plugin_inited = false;

/*

  Terminate the plugin at server shutdown or plugin deinstallation.

  SYNOPSIS
    htp_audit_plugin_deinit()
    Does nothing.

  RETURN VALUE
    0                    success
    1                    failure


*/


static int htp_audit_plugin_deinit(void *arg __attribute__((unused)))
{
  if (!plugin_inited)
    return (0);

  if (!probe_quiting_condition()) {
    return 1;
  }
  htp_audit_deinit_lock();

  htp_audit_deinit_status();

  htp_audit_deinit_variable();

  htp_audit_deinit_filter();

  int ret = Logger::FlushNew();
  if (ret) {
    htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR, "flush log error");
  }

  Logger::Deinitialize();

  plugin_inited = false;

  return (0);
}

/*
  Initialize the plugin at server start or plugin installation.

  SYNOPSIS
    htp_audit_plugin_init()

  DESCRIPTION
    Does nothing.

  RETURN VALUE
    0                    success
    1                    failure
*/


static int htp_audit_plugin_init(void *arg __attribute__((unused)))
{
  switch (0) {
    case 0:
      htp_audit_init_lock();

      htp_audit_init_status();

      htp_audit_init_filter();

      if (htp_audit_read_config_and_init_env())
        break;

      htp_audit_init_variable();

      Logger::Initialize(log_file, error_log_file, enable_buffer);

      int ret = Logger::FlushNew();
      if (ret) {
        htp_audit_logf(HTP_AUDIT_LOG_LEVEL_ERROR, "flush log error");
        break;
      }

      htp_audit_logf(HTP_AUDIT_LOG_LEVEL_INFO, "plugin initialized.");

      plugin_inited = true;

      return (0);
  }

  //出现错误，销毁环境
  htp_audit_plugin_deinit(arg);
  return (1);
}


/*
  SYNOPSIS
    htp_audit_notify()
      thd                connection context
      event_class
      event
  DESCRIPTION
*/

/*static void htp_audit_notify(MYSQL_THD thd __attribute__((unused)),
                              unsigned int event_class,
                              const void *event)*/
static int htp_audit_notify(MYSQL_THD thd,
                            mysql_event_class_t event_class,
                            const void *event)
{
  if (quiting == true)
    return 0;

  number_of_calls_incr();

  htp_audit_process_event(thd, event_class, event);

  //TO DO : error check
  return 0;
}

/*
  Plugin type-specific descriptor
*/

static struct st_mysql_audit htp_audit_descriptor =
    {
        MYSQL_AUDIT_INTERFACE_VERSION,                    /* interface version    */
        NULL,                                             /* release_thd function */
        htp_audit_notify,                                /* notify function      */
        {(unsigned long) MYSQL_AUDIT_GENERAL_ALL,
         (unsigned long) MYSQL_AUDIT_CONNECTION_ALL,
         (unsigned long) MYSQL_AUDIT_PARSE_ALL,
         0, /* This event class is currently not supported. */
         (unsigned long) MYSQL_AUDIT_TABLE_ACCESS_ALL,
         (unsigned long) MYSQL_AUDIT_GLOBAL_VARIABLE_ALL,
         (unsigned long) MYSQL_AUDIT_SERVER_STARTUP_ALL,
         (unsigned long) MYSQL_AUDIT_SERVER_SHUTDOWN_ALL,
         (unsigned long) MYSQL_AUDIT_COMMAND_ALL,
         (unsigned long) MYSQL_AUDIT_QUERY_ALL,
         (unsigned long) MYSQL_AUDIT_STORED_PROGRAM_ALL}
    };

/*
  Plugin library descriptor
*/

mysql_declare_plugin(htp_audit)
    {
        MYSQL_AUDIT_PLUGIN,         /* type                               */
        &htp_audit_descriptor,    /* descriptor                         */
        "HTP_AUDIT",              /* name, install plugin's plugin_name */
        "Htp Corp Jiangyx",       /* author                             */
        "Htp audit plugin",       /* description                        */
        PLUGIN_LICENSE_GPL,
        htp_audit_plugin_init,    /* init function (when loaded)     */
        htp_audit_plugin_deinit,  /* deinit function (when unloaded) */
        0x0001,                     /* version                         */
        htp_audit_status,         /* status variables                */
        htp_audit_sys_var,        /* system variables                */
        NULL,
        0,
    }
mysql_declare_plugin_end;
