cmake_minimum_required(VERSION 3.12)
project(htp_audit_plugin)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(htp_audit_plugin
        audit_item.cc
        cJSON.c
        cJSON.h
        config.c
        config.h
        htp_audit_class.cc
        htp_audit_filter.cc
        htp_audit_filter.h
        htp_audit_main.cc
        htp_audit_vars.cc
        htp_audit_vars.h
        logger.cc)
