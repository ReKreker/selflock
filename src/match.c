#include <string.h>
#include "match.h"

bool match_exact(const char *name_from_proc, const char *name_from_rule) {
    if (strcmp(name_from_proc, name_from_rule) != 0)
        return false;
    return true;
}

bool match_starts_with(const char *name_from_proc, const char *name_from_rule) {
    size_t max_len = strlen(name_from_rule);
    if (strncmp(name_from_proc, name_from_rule, max_len) != 0)
        return false;
    return true;
}

bool match_consists(const char *name_from_proc, const char *name_from_rule) {
    if (strstr(name_from_proc, name_from_rule) == NULL)
        return false;
    return true;
}

typedef bool (*match_t)(const char *proc, const char *rule);

match_t funcs[] = {
        [MATCH_EXACT] = match_exact,
        [MATCH_STARTS_WITH] = match_starts_with,
        [MATCH_CONSIST] = match_consists
};

bool to_match(const char *name_from_proc, const struct sl_rule_t *rule) {
    return funcs[rule->match](name_from_proc, rule->app);
}