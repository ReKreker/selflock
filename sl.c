#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/dir.h>

#include "sl.h"

/**
 * match_* functions to match rule->app and /proc/PID/comm
 * @param name_from_proc
 * @param name_from_rule
 * @return true if matched, so otherwise false
 */
__attribute__((unused)) bool match_exact(const char *name_from_proc, const char *name_from_rule) {
    if (strcmp(name_from_proc, name_from_rule) != 0)
        return false;
    return true;
}

__attribute__((unused)) bool match_starts_with(const char *name_from_proc, const char *name_from_rule) {
    size_t max_len = strlen(name_from_rule);
    if (strncmp(name_from_proc, name_from_rule, max_len) != 0)
        return false;
    return true;
}

__attribute__((unused)) bool match_consists(const char *name_from_proc, const char *name_from_rule) {
    if (strstr(name_from_proc, name_from_rule) == NULL)
        return false;
    return true;
}


/**
 * Utilities
 */

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

bool sl_is_allowed(const struct sl_rule_t *rule){
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


void sl_kill(const char *pid_string){
    pid_t pid = (pid_t) strtol(pid_string, NULL, 10);
    kill(pid, SIGTERM);
    sleep(1);
    kill(pid, SIGKILL);
}

void sl_get_app_name(char *app_name, const char *pid){
    char path[64];
    snprintf(path, 64, "/proc/%s/comm", pid);

    FILE *fd = fopen(path, "r");
    if (!fd) {
        printf("Cannot open file from %s", path);
        abort();
    }
    fread(app_name, 64, 1, fd);
    fclose(fd);

    *strchr(app_name, '\n') = 0;
}


/**
 * API stuff
 */

static struct {
    struct dirent **namelist;
    unsigned int amount;
} ctx;

int sl_find_app(char *app_name, const struct sl_rule_t *rule) {
    for (int j = 0; j < ctx.amount; ++j) {
        char *text_pid = ctx.namelist[j]->d_name;
        sl_get_app_name(app_name, text_pid);
        bool ret = rule->match_fn(app_name, rule->app);
        if (ret) return j;
    }
    return -1;
}

void sl_enum_restrict(const struct sl_rule_t *rules) {
    char app_name[64];
    const struct sl_rule_t *rule;
    for (unsigned int i = 0; (rule = rules+i, rule->app != 0); i++) {
        //assert(i < sizeof(rules)/sizeof(*rules) && "Rules overflow - set SL_RULES_END for last rule");

        // look for application for rule
        int pos = sl_find_app(app_name, rule);
        if (pos == -1) continue; // restricted app didn't run or not found

        // checking
        if (sl_is_allowed(rule))
            continue;

        // killing denied
        printf("App to kill: %s\n", app_name);
        sl_kill(ctx.namelist[pos]->d_name);
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
    snprintf(path, 20, "/proc/%s/", d->d_name);

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