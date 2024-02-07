#ifndef SL_CONFIG_H
#define SL_CONFIG_H


enum action {
    ACTION_ALLOW,
    ACTION_DENY
};

enum match_type {
    MATCH_EXACT,
    MATCH_STARTS_WITH,
    MATCH_CONSIST,
};

// TODO: add weekend-based time ranges
struct sl_time_t {
    const char from[8];      // time range where 'enum action'
    const char to[8];        // is applying (based on current UTC)
};

#define MAX_TIME_RANGES 10
struct sl_rule_t {
    const char app[32];                     // application name from /proc/PID/comm
    enum match_type match;
    enum action act;                        // action for ranges
    struct sl_time_t time[MAX_TIME_RANGES]; // time ranges
};

extern const struct sl_rule_t *rules;
extern const unsigned short rules_amount;
#define IS_LAST_RANGE(time_ptr) ((time_ptr)->to[0] == 0 && (time_ptr)->from[0] == 0)

#endif //SL_CONFIG_H
