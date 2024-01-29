#include "config.h"

// Deny by default if ACTION_ALLOW, so accordingly with ACTION_DENY and allow by default
static const struct sl_rule_t rules_[] = {
        {
                .app = "Telegram",
                .match = MATCH_EXACT,
                .act = ACTION_ALLOW,
                .time = {
                        {.from = "15:00", .to = "16:59"},
                }
        },
        {
                .app = "steam",
                .match = MATCH_CONSIST,
                .act = ACTION_ALLOW,
                .time = {
                        {.from = "18:00", .to = "20:00"},
                }
        },
        {.app = 0} // the last element for size calc
};
const struct sl_rule_t *rules = rules_;