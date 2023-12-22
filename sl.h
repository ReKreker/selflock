#pragma once
#ifndef SELFLOCK_SL_H
#define SELFLOCK_SL_H

#include <stdbool.h>

#include "config.h"

#define SL_NEW0(obj, size) do{ obj = calloc(1,size); if(!obj){ puts("Memory allocation failed"); abort(); } } while(0)
#define SL_FREE(obj) do{ free(obj); obj = NULL; }while(0)

int sl_enum_init();

void sl_enum_restrict(const struct sl_rule_t *rules);

void sl_enum_free();

// Matching functions
__attribute__((unused)) bool match_exact(const char *name_from_proc, const char *name_from_rule);

__attribute__((unused)) bool match_starts_with(const char *name_from_proc, const char *name_from_rule);

__attribute__((unused)) bool match_consists(const char *name_from_proc, const char *name_from_rule);

#endif //SELFLOCK_SL_H
