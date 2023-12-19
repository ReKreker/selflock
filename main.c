#include <stdio.h>
#include <sys/dir.h>
#include <assert.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <sys/inotify.h>
#include <sys/poll.h>

#define SL_NEW0(obj, size) do{ obj = calloc(1,size); if(!obj){ puts("Memory allocation failed"); abort(); } } while(0)
#define SL_FREE(obj) do{ free(obj); obj = NULL; }while(0)

#define SL_RANGES_END {.from = NULL, .to = NULL}
#define SL_RULES_END {.app = NULL}

enum action {
    ACTION_ALLOW,
    ACTION_DENY
};

// TODO: add weekend-based time ranges
struct sl_time_t {
    enum action act;
    char *from;      // time range where 'enum action'
    char *to;        // is applying (based on current UTC)
};

enum match_type {
    MATCHTYPE_EXACT,
    MATCHTYPE_STARTS_WITH,
    MATCHTYPE_CONSIST,
};

#define MAX_TIME_RANGES 10
// currently there is only whitelist time for application
struct sl_rule_t {
    const char *app;                        // application name from /proc/PID/comm
    enum match_type mt;                     // matching type for app name
    struct sl_time_t time[MAX_TIME_RANGES]; // time ranges
};

// Allow by default. The last rules are more significant than the first ones
static struct sl_rule_t rules[] = {
        [__COUNTER__] = {
                .app = "Telegram",
                .mt = MATCHTYPE_EXACT,
                .time = {
                        [0] = {.act = ACTION_DENY, .from = "13:37", .to = "15:37"},
                        [1] = SL_RANGES_END
                }
        },
        [__COUNTER__] = SL_RULES_END
};

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

int sl_enum_processes(struct dirent ***namelist){
    int res = scandir("/proc", namelist, sl_selector, alphasort);
    if (res <= 0){
        puts("Scandir error for /proc\n");
        abort();
    }
    return res;
}

// return 0 if matched, -1 if not
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

void sl_get_app_name(char *app_name, const char *pid){
    char path[64];
    snprintf(path, 64, "/proc/%s/comm", pid);

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

    bool allow_flag = true;
    int i = 0;
    struct sl_time_t t;

    while ((t = rule->time[i], t.from && t.to)){
        from_epoch = sl_parse_time(*now, t.from);
        to_epoch = sl_parse_time(*now, t.to);
        assert(from_epoch != -1 && to_epoch != -1);
        switch (t.act) {
            case ACTION_ALLOW:
                if (from_epoch <= now_epoch && now_epoch <= to_epoch)
                    allow_flag = true;
                break;
            case ACTION_DENY:
                if (from_epoch <= now_epoch && now_epoch <= to_epoch)
                    allow_flag = false;
                break;
            default:
                puts("Not implemented");
                abort();
        }
        i++;
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

int sl_restrict(struct dirent ***namelist, int enum_amount){
    char app_name[64];
    for (unsigned int i = 0; ; ++i) {
        assert(i < sizeof(rules)/sizeof(*rules) && "Rules overflow - set SL_RULES_END for last rule");
        struct sl_rule_t *rule = &rules[i];
        if (rule->app == 0)
            break;

        // look for application for rule
        int ret = -1;
        unsigned int j;
        for (j = 0; j < enum_amount; ++j) {
            char *text_pid = (*namelist)[j]->d_name;
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
        sl_kill((*namelist)[j]->d_name);
    }
    return 0;
}

void sl_free_enum(struct dirent ***namelist, int enum_amount){
    for (int i = 0; i < enum_amount; ++i) {
        free((*namelist)[i]);
        (*namelist)[i] = NULL;
    }
    free(*namelist);
    *namelist = NULL;
}

int main() {
    // TODO: add smth like poll to wait until new process in /proc
    struct dirent **namelist;
    int enum_amount = sl_enum_processes(&namelist);
    assert(enum_amount > 0);
    sl_restrict(&namelist, enum_amount);
    sl_free_enum(&namelist, enum_amount);
}
