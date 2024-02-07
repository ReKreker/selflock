#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "utils.h"

time_t sl_parse_time(struct tm base, const char *time_range) {
    int res = sscanf(time_range, "%d:%d", &base.tm_hour, &base.tm_min);
    if (res != 2) {
        printf("Wrong time format '%s' use something like '13:37'", time_range);
        abort();
    }

    time_t tmp = mktime(&base);
    if (tmp == -1) {
        printf("Cannot convert time(%s) to epoch", time_range);
        abort();
    }
    return tmp;
}

bool sl_is_allowed(const struct sl_rule_t *rule) {
    const time_t tt = time(NULL);
    struct tm *now = localtime(&tt);
    time_t from_epoch, to_epoch, now_epoch = mktime(now);

    // Default disallow for ACTION_ALLOW ranges & allow for ACTION_DENY
    bool allow_flag = rule->act == ACTION_DENY;
    const struct sl_time_t *t;

    for (int i = 0; !IS_LAST_RANGE(&rule->time[i]); ++i) {
        t = &rule->time[i];
        from_epoch = sl_parse_time(*now, t->from);
        to_epoch = sl_parse_time(*now, t->to);
        assert(from_epoch != -1 && to_epoch != -1);

        if (from_epoch <= now_epoch && now_epoch <= to_epoch) {
            allow_flag ^= 1;
            break;
        }
        assert(i <= MAX_TIME_RANGES && "Time ranges overflow - set SL_RANGES_END for last time range");
    }

    return allow_flag;
}

// TODO: make app killing in another thread to avoid program locking
void sl_kill(const char *pid_string) {
    char app[64], cmd[0x100];

    sl_get_app_name(app, pid_string);
    snprintf(cmd, 0x100, "notify-send -t 5000 -a \"Selflock\" \"Application %s will be killed in 5 seconds!\"", app);

    system(cmd);
    sleep(5);
    pid_t pid = (pid_t) strtol(pid_string, NULL, 10);
    kill(pid, SIGTERM);
    sleep(1);
    kill(pid, SIGKILL);
}

// TODO: add ability to choose between /proc/%s/comm & /proc/%s/cmdline
void sl_get_app_name(char app_name[64], const char *pid) {
    char path[64];
    snprintf(path, 64, "/proc/%s/comm", pid);

    FILE *fd = fopen(path, "r");
    if (!fd) {
        // when process is closed by OS
        if (errno == ENOENT) {
            app_name[0] = 0;
            return;
        }
        printf("Cannot open file from %s", path);
        abort();
    }
    fread(app_name, 64, 1, fd);
    fclose(fd);

    *strchr(app_name, '\n') = 0;
}