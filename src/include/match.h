#ifndef SELFLOCK_MATCH_H
#define SELFLOCK_MATCH_H

#include <stdbool.h>

#include "config.h"

bool to_match(const char *name_from_proc, const struct sl_rule_t *rule);

#endif //SELFLOCK_MATCH_H
