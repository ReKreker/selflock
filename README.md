# Selflock

This utility is designed to prevent users from spending excessive time in specific applications by imposing time limits
on their usage. The configuration of the utility is achieved by editing the rules.

## Usage

To use this utility, simply edit the rules to specify the time limits for different applications. The utility
will then enforce these limits, blocking access to applications once the specified time threshold is reached.

## Example Configuration

In `src/config.c` there is tables with rules:

```c
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
        }
};
```

This utility aims to promote a balanced and efficient use of time by preventing excessive engagement with specific
applications.

_The name for application is extracted from `/proc/PID/comm`._

## Existing matching functions

- **MATCH_EXACT** - check if `rule->app` and `/proc/PID/comm` are the same
- **MATCH_STARTS_WITH** - check if `/proc/PID/comm` starts with `rule->app`
- **MATCH_CONSIST** - check if `rule->app` is substring of `/proc/PID/comm`

## Deps

1) notify-send - to send notifications

## Build

```
git clone --recurse-submodules https://github.com/ReKreker/selflock
cd selflock
cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release
cd build
make
```