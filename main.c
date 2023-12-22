#include <assert.h>

#include "sl.h"

// Allow by default. The last rules are more significant than the first ones
// TODO: rewrite 'Deny by default' if there is only ACTION_ALLOW, so accordingly with ACTION_DENY
static struct sl_rule_t rules[] = {
        [__COUNTER__] = {
                .app = "Telegram",
                .mt = MATCHTYPE_EXACT,
                .act = ACTION_ALLOW,
                .time = {
                        [0] = {.from = "13:37", .to = "14:37"},
                        [1] = SL_RANGES_END
                }
        },
        [__COUNTER__] = SL_RULES_END
};

int main() {
    // TODO: add smth like poll to wait until new process in /proc
    struct dirent **namelist;
    int enum_amount = sl_enum_processes(&namelist);
    assert(enum_amount > 0);
    sl_restrict(&namelist, enum_amount);
    sl_free_enum(&namelist, enum_amount);
}
