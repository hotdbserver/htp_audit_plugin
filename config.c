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
#include "config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifndef NULL
#define NULL 0
#endif

#define NOUSE (void)

typedef enum CRET_enum {
  SUCCESS = 0,
  ERROR = 1
} CRET;

struct config_parser_struct {
  config_group_t *current_group;
  config_item_t *current_item;
};
typedef struct config_parser_struct config_parser_t;

#define END_CHAR (0)
#define DESTROY_GROUP_ITEM_ONLY 1
#define DESTROY_GROUP_ALL 2

static config_t *config_read_from_file(FILE *file);

static void config_destroy_group(config_group_t *group, int flag);

static void config_init(config_t *config);

static void config_group_init(config_group_t *group);

static void config_item_init(config_item_t *item);

static void config_parser_init(config_parser_t *parser, config_t *config);

static CRET config_parse(config_t *config, FILE *file);

static CRET config_parse_group(config_t *config, char *line, config_parser_t *parser, int line_len);

static CRET config_parse_item(config_t *config, char *line, config_parser_t *parser, int line_len);

#ifdef WINDOWS
#define THREAD_LOCAL __declspec(thread)
#else
#define THREAD_LOCAL __thread
#endif
static THREAD_LOCAL config_err_t config_err = {0, 0};

static config_err_t *get_thd_err() {
  return &config_err;
}

/*
  return :
  1 is empty line
  0 isn't empty line
*/
inline int is_empty_line(const char *input, int len) {
  int i = 0;
  for (i = 0; i < len; i++) {
    if (!isspace(input[i]))
      return 0;
  }

  return 1;
}

config_t *config_read(char *file_path) {
  FILE *file = fopen(file_path, "r");
  config_t *config = NULL;
  if (file == NULL)
    return NULL;

  config = config_read_from_file(file);

  fclose(file);

  return config;
}

void config_destroy(config_t *config) {
  config_group_t *current, *next;
  if (config == NULL)
    return;

  config_destroy_group(&config->anonymous, DESTROY_GROUP_ITEM_ONLY);

  current = config->groups;
  while (current != NULL) {
    next = current->next;
    config_destroy_group(current, DESTROY_GROUP_ALL);
    current = next;
  }
  free(config);
}

config_err_t config_get_err() {
  return config_err;
}

static config_t *config_read_from_file(FILE *file) {
  config_t *config = (config_t *) malloc(sizeof(config_t[1]));
  CRET ret;

  if (config == NULL)
    return NULL;

  config_init(config);

  ret = config_parse(config, file);
  if (ret != SUCCESS) {
    config_destroy(config);
    return NULL;
  }

  return config;
}

static void config_destroy_group(config_group_t *group, int flag) {
  config_item_t *current, *next;

  assert(group != NULL);

  current = group->items;
  while (current != NULL) {
    next = current->next;
    free(current);
    current = next;
  }
  if (flag == DESTROY_GROUP_ALL)
    free(group);
}

static CRET config_parse_group(config_t *config, char *line, config_parser_t *parser, int line_line) {
  int len = line_line;
  int name_len = 0;
  config_group_t *group;
  int i;

  //获取group的名字
  for (i = 1; i < len; i++) {
    if (line[i] == ']') {
      break;
    }
    name_len++;
  }

  //TODO : 检查

  //分配group的空间
  group = (config_group_t *) malloc(sizeof(config_group_t[1]));
  if (group == NULL)
    return ERROR;
  config_group_init(group);

  //获取名字
  strncpy(group->name, line + 1, name_len);
  group->name[name_len] = 0;

  //将group加入到config中
  if (config->groups == &config->anonymous) {
    //碰到的第一个用户输入group
    config->groups = group;
  } else {
    //后续的group
    assert(parser->current_group != NULL
               && parser->current_group != &config->anonymous);

    parser->current_group->next = group;
  }

  //填写config和group的统计信息
  group->number = config->group_amount;
  config->group_amount++;

  //更新分析器状态
  parser->current_group = group;
  parser->current_item = NULL;

  return SUCCESS;
}

static CRET config_parse_item(config_t *config, char *line, config_parser_t *parser, int line_len) {
  int len = line_len;
  int key_len = 0;
  int value_len = 0;
  config_item_t *item;
  char *key = NULL, *value = NULL;
  int i;

  NOUSE (config);
  //获取key，value的内容
  key = line;
  for (i = 0; i < len; i++) {
    if (line[i] == '=')
      break;
    key_len++;
  }
  value = line + key_len + 1;
  for (i = (key_len + 1); i < len; i++) {
    if (line[i] == '\n' || line[i] == '\r')
      break;
    value_len++;
  }

  //to do : 进行内容检查

  //分配item空间
  item = (config_item_t *) malloc(sizeof(config_item_t[1]));
  if (item == NULL)
    return ERROR;
  config_item_init(item);
  strncpy(item->key, key, key_len);
  item->key[key_len] = 0;
  item->key_len = key_len;
  strncpy(item->value, value, value_len);
  item->value[value_len] = 0;
  item->value_len = value_len;

  //更新分析器状态
  if (parser->current_item == NULL) {
    //当前group的第一个item
    assert(parser->current_group->items == NULL);
    parser->current_group->items = item;
    parser->current_item = item;
  } else {
    parser->current_item->next = item;
    parser->current_item = item;
  }

  return SUCCESS;
}

static CRET config_parse_line(config_t *config, char *line, config_parser_t *parser) {
  int len;

  assert(line != NULL);

  len = strlen(line);

  //注释行
  if (line[0] == '#')
    return SUCCESS;
  //空行
  if (is_empty_line(line, len))
    return SUCCESS;

  if (line[0] == '[')
    return config_parse_group(config, line, parser, len);

  return config_parse_item(config, line, parser, len);
}

static CRET config_parse(config_t *config, FILE *file) {
  config_parser_t parser;
  char buffer[16 * 1024];
  char *line;
  CRET ret = SUCCESS;
  int line_no = 0;
  config_err_t *err;

  config_parser_init(&parser, config);

  do {
    line = fgets(buffer, sizeof(buffer), file);
    if (line == NULL) {
      if (!feof(file)) {
        //出现错误
        err = get_thd_err();
        err->line_no = line_no;
        return ERROR;
      }
    } else {
      line_no++;
      ret = config_parse_line(config, line, &parser);
      //如果出现错误，返回line_no的行号
      if (ret != SUCCESS) {
        err = get_thd_err();
        err->line_no = line_no;
      }
    }
  } while (line != NULL && ret == SUCCESS);

  return ret;
}

static void config_init(config_t *config) {
  config_group_init(&config->anonymous);
  config->groups = &config->anonymous;
  config->group_amount = 0;
}

#define GROUP_NUMBER_UNSETTED (-1)

static void config_group_init(config_group_t *group) {
  group->items = NULL;
  group->name[0] = END_CHAR;
  group->name_len = 0;
  group->next = NULL;
  group->number = GROUP_NUMBER_UNSETTED;
}

static void config_item_init(config_item_t *item) {
  item->key[0] = END_CHAR;
  item->key_len = 0;
  item->value[0] = END_CHAR;
  item->value_len = 0;
  item->next = NULL;
}

static void config_parser_init(config_parser_t *parser, config_t *config) {
  parser->current_group = &config->anonymous;
  parser->current_item = NULL;
}
