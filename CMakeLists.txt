# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#INCLUDE(${MYSQL_CMAKE_SCRIPT_DIR}/compile_flags.cmake)

# If current CMAKE_C_FLAGS is with Werror, turn it off to compile successfully
#IF(CMAKE_C_FLAGS MATCHES "-Werror")
#    STRING(REGEX REPLACE "-Werror( |$)" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
#ENDIF(CMAKE_C_FLAGS MATCHES "-Werror")

MYSQL_ADD_PLUGIN(htp_audit  htp_audit_filter.cc htp_audit_vars.cc htp_audit_class.cc audit_item.cc cJSON.c logger.cc config.c
        htp_audit_main.cc  MODULE_ONLY MODULE_OUTPUT_NAME "htp_audit")
#add_definitions(-Wno-error)
#INSTALL(FILES htp_audit.cnf DESTINATION ${INSTALL_PLUGINDIR})
