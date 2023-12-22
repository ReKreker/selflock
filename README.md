# Selflock

This utility is designed to prevent users from spending excessive time in specific applications by imposing time limits on their usage. The configuration of the utility is achieved by editing the rules[] variable, allowing for customization of time limits for different applications.

## Features
- **Time Limit Setting**: Users can set specific time limits for individual applications by modifying the rules[] variable.
- **Application Blocking**: Once the allotted time limit for an application is reached, the utility will block further usage of that application.
- **Customization**: The utility provides flexibility for users to tailor time limits based on their preferences and requirements.
- **Efficiency**: By preventing excessive usage of specific applications, this utility promotes better time management and productivity.

## Usage
To use this utility, simply edit the rules[] variable to specify the time limits for different applications. The utility will then enforce these limits, blocking access to applications once the specified time threshold is reached.

## Example Configuration
In `main.c` there is tables with rules:
```c
static const struct sl_rule_t rules[] = {
        [__COUNTER__] = {
                .app = "Telegram",
                .match_fn = match_exact,
                .act = ACTION_ALLOW,
                .time = {
                        [0] = {.from = "13:37", .to = "14:37"},
                        [1] = {.from = "18:00", .to = "19:00"},
                        [2] = SL_RANGES_END
                } // allow Telegram only at 13:37-14:37 & 18:00-19:00
        },
        [__COUNTER__] = {
                .app = "Steam",
                .match_fn = match_contains,
                .act = ACTION_DENY,
                .time = {
                        [0] = {.from = "12:00", .to = "18:00"},
                        [1] = SL_RANGES_END
                } // allow ".*Steam.*" app all day except 12:00-18:00 
        },
        [__COUNTER__] = SL_RULES_END
};
```

By configuring the rules[] variable as shown above, users can effectively manage their time spent in various applications.

This utility aims to promote a balanced and efficient use of time by preventing excessive engagement with specific applications.

The name for application is extracted from `/proc/PID/comm`.