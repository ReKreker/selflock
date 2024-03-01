#pragma once
#ifndef SELFLOCK_UTILS_H
#define SELFLOCK_UTILS_H

#include <time.h>
#include <stdbool.h>

#include "zlog.h"
#include "config.h"

#define TIMEOUT_BEFORE_KILL 10u

extern zlog_category_t *c;

typedef struct {
    pid_t pid;
    struct timeval timestamp;
} sl_kill_list_t;

#define KILL_LIST_MAX_SIZE 10u

time_t sl_parse_time(struct tm base, const char *time_range);

bool sl_is_allowed(const struct sl_rule_t *rule);

void sl_kill(const char *pid_string);

void sl_get_app_name(char app_name[64], const char *pid);

#endif //SELFLOCK_UTILS_H
