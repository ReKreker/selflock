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
        // Deny abnormal work
        {
                .app = "CLion",
                .match = MATCH_STARTS_WITH,
                .act = ACTION_DENY,
                .time = {
                        {.from = "00:00", .to = "06:00"},
                        {.from = "20:00", .to = "23:59"}
                }
        },
        {
                .app = "PyCharm",
                .match = MATCH_STARTS_WITH,
                .act = ACTION_DENY,
                .time = {
                        {.from = "00:00", .to = "06:00"},
                        {.from = "20:00", .to = "23:59"}
                }
        },
        {
                .app = "CodeBrowser",
                .match = MATCH_STARTS_WITH,
                .act = ACTION_DENY,
                .time = {
                        {.from = "00:00", .to = "06:00"},
                        {.from = "20:00", .to = "23:59"}
                }
        }
};

const struct sl_rule_t *rules = (struct sl_rule_t *) rules_;
const unsigned short rules_amount = sizeof(rules_) / sizeof(*rules_);
