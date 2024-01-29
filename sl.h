#pragma once
#ifndef SELFLOCK_SL_H
#define SELFLOCK_SL_H

#include <stdbool.h>

#include "config.h"

#define SL_NEW0(obj, size) do{ obj = calloc(1,size); if(!obj){ puts("Memory allocation failed"); abort(); } } while(0)
#define SL_FREE(obj) do{ free(obj); obj = NULL; }while(0)

int sl_enum_init();

void sl_enum_restrict();

void sl_enum_free();

#endif //SELFLOCK_SL_H
