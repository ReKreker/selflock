#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>
#include <sys/dir.h>

#include "sl.h"

static struct {
    struct dirent **namelist;
    int amount;
} ctx;

int sl_match(const char *app_name, struct sl_rule_t *rule){
    switch (rule->mt) {
        case MATCHTYPE_EXACT:
            if (!strcmp(app_name, rule->app))
                return 0;
            break;
        default:
            puts("Not implemented");
            abort();
    }
    return -1;
}

time_t sl_parse_time(struct tm base, const char *time_range){
    int res = sscanf(time_range, "%d:%d", &base.tm_hour, &base.tm_min);
    if (res != 2) {
        printf("Wrong time format '%s' use something like '13:37'", time_range);
        abort();
    }

    time_t tmp = mktime(&base);
    if (tmp == -1){
        printf("Cannot convert time(%s) to epoch", time_range);
        abort();
    }
    return tmp;
}

bool sl_is_allowed(struct sl_rule_t *rule){
    const time_t tt = time(NULL);
    struct tm *now = localtime(&tt);
    time_t from_epoch, to_epoch, now_epoch = mktime(now);

    // Default disallow for ACTION_ALLOW ranges & allow for ACTION_DENY
    bool allow_flag = rule->act == ACTION_DENY;
    struct sl_time_t t;

    for (int i = 0; (t = rule->time[i], t.from && t.to) ; ++i) {
        from_epoch = sl_parse_time(*now, t.from);
        to_epoch = sl_parse_time(*now, t.to);
        assert(from_epoch != -1 && to_epoch != -1);

        if (from_epoch <= now_epoch && now_epoch <= to_epoch) {
            allow_flag ^= 1;
            break;
        }
        assert(i <= MAX_TIME_RANGES && "Time ranges overflow - set SL_RANGES_END for last time range");
    }

    return allow_flag;
}

void sl_kill(char *pid_string){
    pid_t pid = (pid_t) strtol(pid_string, NULL, 10);
    kill(pid, SIGTERM);
    sleep(1);
    kill(pid, SIGKILL);
}

void sl_get_app_name(char *app_name, const char *pid){
    char path[64];
    snprintf(path, 64, "/proc/%s/comm", pid);

    // TODO: rewrite with fopen
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Cannot open file from %s", path);
        abort();
    }
    read(fd, path, 64); // reuse variable for path of executed bin
    close(fd);

    *strchr(path, '\n') = 0;
    strncpy(app_name, path, 64);
}

void sl_enum_restrict(struct sl_rule_t *rules) {
    char app_name[64];
    struct sl_rule_t *rule;
    for (unsigned int i = 0; (rule = rules+i, rule->app != 0); i++) {
        //assert(i < sizeof(rules)/sizeof(*rules) && "Rules overflow - set SL_RULES_END for last rule");

        // look for application for rule
        int ret = -1;
        unsigned int j;
        for (j = 0; j < ctx.amount; ++j) {
            char *text_pid = ctx.namelist[j]->d_name;
            sl_get_app_name(app_name, text_pid);
            ret = sl_match(app_name, rule);
            if (!ret) break;
        }
        if (ret == -1) continue; // restricted app didn't run

        // checking
        if (sl_is_allowed(rule))
            continue;

        // killing denied
        printf("To kill: %s\n", app_name);
        sl_kill(ctx.namelist[j]->d_name);
    }
}

int sl_selector(const struct dirent *d){
    char letter;
    const char *name;
    char path[20];
    struct stat stb;

    // filter non-dir
    if (d->d_type != DT_DIR)
        return 0;

    // filter non-numeric
    name = d->d_name;
    while ((letter = *name)){
        if (letter < '0' || '9' < letter)
            return 0;
        name++;
    }

    // filter dirs without current user creds
    // TODO: find another way to check is process killable by current user
    snprintf(path, 20-1, "/proc/%s/", d->d_name);

    if(stat(path, &stb)){
        printf("Failed stat for %s\n", path);
        abort();
    }

    if (stb.st_uid != geteuid() && stb.st_gid != getegid())
        return 0;

    return 1;
}

int sl_enum_init(){
    if(ctx.namelist != NULL){
        puts("Hanging pointer - internal context didn't freed and nullified");
        abort();
    }

    int res = scandir("/proc", &ctx.namelist, sl_selector, alphasort);
    if (res <= 0){
        puts("Scandir error for /proc\n");
        abort();
    }
    ctx.amount = res;
    return res;
}

void sl_enum_free(){
    for (int i = 0; i < ctx.amount; ++i) {
        free(ctx.namelist[i]);
        ctx.namelist[i] = NULL;
    }
    free(ctx.namelist);
    ctx.namelist = NULL;
}