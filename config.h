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
#ifndef CONFIG_H_
#define CONFIG_H_

/*
配置例子
[group1]
#keyold=valueold
key1=value1
key2=value2

[group2]
key1=value1
key2=value2
*/

/*
使用说明：配置文件
一、配置组(group)
1、[]所括为配置组的名字，在下一个[]出现之前的配置项，都属于当前的配置组
2、配置组的名字不可超过128字节长度
3、存在一个无名组，用以记录那些不在任何组之内的配置。其他组必须存在名字
二、配置项
1、配置项由key/value串组成
2、key长度不可超过128字节，value串的长度不可超过2048字节
3、=两边空格作为key的名字或者value的内容，不进行过滤
三、其他
1、不会对同名组进行去重/覆盖
2、不会对组内同名key进行去重/覆盖
3、不支持宽字符
*/

/*
使用说明：输出
1、config_t结构中保存无名组合配置组的单向链表，最后一个配置组指向下一配置组的指针为空（NULL/0）
2、config_group_t结构中保存配置项的链表，最后一个配置项指向下一配置项的指针为空（NULL/0）
*/

#ifdef __cplusplus
extern "C" { /* Assume C declarations for C++   */
#endif  /* __cplusplus */

#define KEY_LENGTH (128)
#define KEY_BUFFER_SIZE (KEY_LENGTH + 1)
#define VALUE_LENGTH (2048)
#define VALUE_BUFFER_SIZE (VALUE_LENGTH + 1)
#define GROUP_NAME_LENGTH (128)
#define GROUP_NAME_BUFFER_SIZE (GROUP_NAME_LENGTH + 1)

#define CONFIG_ERROR_NOFILE (1)
#define CONFIG_ERROR_LINE   (2)
//#define HTP_AUDIT_CONFIG_FILE "htp_audit.cnf"


struct config_err_struct {
  int err_no;   //出现错误时的错误号，0表示无错误
  int line_no;  //出现错误时的行号
};
typedef struct config_err_struct config_err_t;

struct config_item_struct {
  char key[KEY_BUFFER_SIZE];
  int key_len;
  char value[VALUE_BUFFER_SIZE];
  int value_len;
  void *next;
};
typedef struct config_item_struct config_item_t;

struct config_group_struct {
  char name[GROUP_NAME_BUFFER_SIZE];
  int name_len;
  int number; /*0-based。配置文件中，该group的位置。第一个配置组的值为0*/
  config_item_t *items;
  void *next;
};
typedef struct config_group_struct config_group_t;

struct config_struct {
  config_group_t anonymous; /*在没有指定任何group的配置项，存放在这里*/
  int group_amount; /*配置的文件中的group数目*/
  config_group_t *groups;
};
typedef struct config_struct config_t;

config_t *config_read(char *file);

void config_destroy(config_t *config);

config_err_t config_get_err();

#ifdef __cplusplus
}                                    /* End of extern "C" { */
#endif  /* __cplusplus */

#endif //CONFIG_H_
