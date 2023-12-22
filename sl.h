#ifndef SELFLOCK_SL_H
#define SELFLOCK_SL_H

#include <sys/dir.h>

#include "config.h"

#define SL_NEW0(obj, size) do{ obj = calloc(1,size); if(!obj){ puts("Memory allocation failed"); abort(); } } while(0)
#define SL_FREE(obj) do{ free(obj); obj = NULL; }while(0)

int sl_enum_processes(struct dirent ***namelist);

int sl_restrict(struct dirent ***namelist, int enum_amount, struct sl_rule_t *rules);

void sl_free_enum(struct dirent ***namelist, int enum_amount);


#endif //SELFLOCK_SL_H
