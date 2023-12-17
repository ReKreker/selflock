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

#define SL_NEW0(obj, size) do{ obj = calloc(1,size); assert(obj); } while(0)
#define SL_FREE(obj) do{ free(obj); obj = NULL; }while(0)

enum action {
    //ACTION_NOTHING, // not implemented
    ACTION_ALLOW,
    //ACTION_DISALLOW // not implemented
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

static struct sl_rule_t rules[] = {
        [__COUNTER__] = {
                .app = "Telegram",
                .mt = MATCHTYPE_EXACT,
                .time = {
                        [0] = {.act = ACTION_ALLOW, .from = "13:37", .to = "14:37"},
                        [1] = {.from = NULL, .to = NULL} // set "from" or "to" to NULL to mark end of time ranges
                }
        },
        [__COUNTER__] = {.app = NULL} // mark end of rules
};

int sl_selector(const struct dirent *d){
    // filter non-dir
    if (d->d_type != DT_DIR)
        return 0;

    // filter non-numeric
    char letter;
    const char *name = d->d_name;
    while ((letter = *name)){
        if (letter < '0' || '9' < letter)
            return 0;
        name++;
    }

    // filter dirs without current user creds
    char path[20];
    snprintf(path, 20, "/proc/%s/", d->d_name);

    struct stat stb;
    if(stat(path, &stb)){
        printf("Failed stat for %s\n", path);
        assert(0);
    }

    if (stb.st_uid != geteuid() && stb.st_gid != getegid())
        return 0;

    return 1;
}

int sl_enum_processes(struct dirent ***namelist){
    int res = scandir("/proc", namelist, sl_selector, alphasort);
    assert(res > 0 && "Scandir error");
    return res;
}

// return 0 if matched, -1 if not
int sl_match(const char *app_name, struct sl_rule_t *rule){
    switch (rule->mt) {
        case MATCHTYPE_EXACT:
            if (!strcmp(app_name, rule->app))
                return 0;
            break;
        case MATCHTYPE_STARTS_WITH:
            assert(0 && "Not implemented");
        case MATCHTYPE_CONSIST:
            assert(0 && "Not implemented");
        default:
            assert(0 && "Not implemented");
    }
    return -1;
}

void sl_get_app_name(char *app_name, const char *pid){
    char path[64];
    snprintf(path, 64, "/proc/%s/comm", pid);

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("Cannot open file from %s", path);
        assert(0);
    }
    read(fd, path, 64); // reuse variable for path of executed bin
    close(fd);

    *strchr(path, '\n') = 0;
    strncpy(app_name, path, 64);
}

void sl_parse_time(const char *time_from_rule, long *hours, long *mins){
    char *tmp;
    errno = 0;
    *hours = strtol(time_from_rule, &tmp, 10);
    if (tmp[0] != ':') goto wrong_format;
    *mins = strtol(&tmp[1], &tmp, 10);
    if (errno) goto wrong_format;

    return;

wrong_format:
    printf("Wrong time format '%s' use something like '13:37'", time_from_rule);
    assert(0);
}

bool sl_is_allowed(struct sl_rule_t *rule){
    const time_t tt = time(NULL);
    struct tm *now = localtime(&tt);

    bool allow_flag = false;
    long f_hours, f_mins, t_hours, t_mins; // from & to int variables
    int i = 0;
    struct sl_time_t t;
    while ((t = rule->time[i], t.from || t.to)){
        sl_parse_time(t.from, &f_hours, &f_mins);
        sl_parse_time(t.to, &t_hours, &t_mins);
        // TODO: rewrite this ugly logic
        switch (t.act) {
            case ACTION_ALLOW:
                if (f_hours < now->tm_hour && now->tm_hour < t_hours) {
                    allow_flag = true;
                } else if (f_hours == now->tm_hour && now->tm_hour < t_hours
                        && f_mins <= now->tm_min) {
                    allow_flag = true;
                } else if (f_hours == now->tm_hour && now->tm_hour == t_hours
                        && f_mins <= now->tm_min && now->tm_min <= t_mins){
                    allow_flag = true;
                } else if (f_hours < now->tm_hour && now->tm_hour == t_hours
                           && now->tm_min <= t_mins){
                    allow_flag = true;
                }
                break;
            default:
                assert(0 && "Not implemented");
        }
        i++;
    }
    return allow_flag;
}

int sl_restrict(struct dirent ***namelist, int enum_amount){
    char app_name[64];
    for (unsigned int i = 0; ; ++i) {
        assert(i < sizeof(rules)/sizeof(*rules) && "Rules overflow - set '.app = NULL' for last rule");
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
        pid_t pid = (pid_t) strtol((*namelist)[j]->d_name, NULL, 10);
        kill(pid, SIGTERM);
        sleep(1);
        kill(pid, SIGKILL);

    }
    return 0;
}

void sl_free_enum(struct dirent ***namelist, int enum_amount){
    for (int i = 0; i < enum_amount; ++i)
        free((*namelist)[i]);
    free(*namelist);
}

int main() {
    // TODO: add smth like poll to wait until new process in /proc
    struct dirent **namelist;
    int enum_amount = sl_enum_processes(&namelist);
    sl_restrict(&namelist, enum_amount);
    sl_free_enum(&namelist, enum_amount);
}
