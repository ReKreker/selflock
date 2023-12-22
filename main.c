#include <assert.h>
#include <unistd.h>

#include "sl.h"

// Deny by default if ACTION_ALLOW, so accordingly with ACTION_DENY and allow by default
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
    // There is no way to get pid except repeatedly read /proc/
    int rc;
    while (1){
        rc = sl_enum_init();
        assert(rc > 0);
        sl_enum_restrict(rules);
        sl_enum_free();

        sleep(2);
    }
}
