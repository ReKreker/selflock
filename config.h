#ifndef SL_CONFIG_H
#define SL_CONFIG_H

#define SL_RANGES_END {.from = 0, .to = 0}
#define SL_RULES_END {.app = 0}

enum action {
    ACTION_ALLOW,
    ACTION_DENY
};

// TODO: add weekend-based time ranges
struct sl_time_t {
    char *from;      // time range where 'enum action'
    char *to;        // is applying (based on current UTC)
};

// TODO: rewrite to callback-based match_type
enum match_type {
    MATCHTYPE_EXACT,
    MATCHTYPE_STARTS_WITH,
    MATCHTYPE_CONSIST,
};

#define MAX_TIME_RANGES 10
struct sl_rule_t {
    const char *app;                        // application name from /proc/PID/comm
    enum match_type mt;                     // matching type for app name
    enum action act;                        // action for ranges
    struct sl_time_t time[MAX_TIME_RANGES]; // time ranges
};

#endif //SL_CONFIG_H
