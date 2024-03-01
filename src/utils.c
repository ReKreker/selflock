#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <sys/time.h>
#include "utils.h"

zlog_category_t *c;

time_t sl_parse_time(struct tm base, const char *time_range) {
    int res = sscanf(time_range, "%d:%d", &base.tm_hour, &base.tm_min);
    if (res != 2) {
        zlog_fatal(c, "Wrong time format '%s' use something like '13:37'", time_range);
        abort();
    }

    time_t tmp = mktime(&base);
    if (tmp == -1) {
        zlog_fatal(c, "Cannot convert time(%s) to epoch", time_range);
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

void sl_show_kill_notif(const char *pid_string) {
    char app[64], cmd[0x100];
    sl_get_app_name(app, pid_string);
    snprintf(cmd, 0x100, "notify-send -t 5000 -a \"Selflock\" \"Application '%s' will be killed in %u seconds!\"",
             app,
             TIMEOUT_BEFORE_KILL);
    system(cmd);
}

static sl_kill_list_t klist[KILL_LIST_MAX_SIZE] = {};

// Return 0 if new, -1 if exists
int sl_add_to_klist(struct timeval *tv, pid_t pid) {
    for (unsigned int i = 0; i < KILL_LIST_MAX_SIZE; ++i) {
        if (klist[i].pid == pid) return -1;
        if (klist[i].pid != 0) continue;
        klist[i].pid = pid;
        memcpy(&klist[i].timestamp, tv, sizeof(*tv));
        return 0;
    }
    zlog_fatal(c, "Overflow klist!");
    abort();
}

void sl_update_klist(unsigned index) {
    int rc;

    rc = kill(klist[index].pid, SIGTERM);
    if (!rc) goto flush_entry;
    zlog_error(c, "Cannot send SIGTERM to %d: %s", klist[index].pid, strerror(errno));
    rc = kill(klist[index].pid, SIGKILL);
    if (!rc) goto flush_entry;
    zlog_fatal(c, "Cannot send SIGKILL to %d: %s", klist[index].pid, strerror(errno));
    abort();

    flush_entry:
    klist[index].pid = 0;
    memset(&klist[index].timestamp, 0, sizeof(klist[index].timestamp));
}

void sl_kill(const char *pid_string) {
    long long pid_ll;
    unsigned i;
    int rc;
    struct timeval tv;
    pid_t pid;

    pid_ll = strtoll(pid_string, NULL, 10);
    assert(pid_ll != 0 && pid_ll != LLONG_MIN && pid_ll != LLONG_MIN && "Parsing pid error");
    pid = (pid_t) pid_ll;
    assert(pid != 0 && "PID is zero");

    rc = gettimeofday(&tv, NULL);
    if (rc) {
        zlog_fatal(c, "Cannot get timestamp: %s", strerror(errno));
        return;
    }

    for (i = 0; i < KILL_LIST_MAX_SIZE; ++i)
        if (klist[i].pid == pid && klist[i].timestamp.tv_sec + TIMEOUT_BEFORE_KILL < tv.tv_sec) {
            sl_update_klist(i);
            return;
        }

    rc = sl_add_to_klist(&tv, pid);
    if (rc == 0)
        sl_show_kill_notif(pid_string);
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
        zlog_fatal(c, "Cannot open file from %s", path);
        abort();
    }
    fread(app_name, 64, 1, fd);
    fclose(fd);

    *strchr(app_name, '\n') = 0;
}