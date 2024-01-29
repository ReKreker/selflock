#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/dir.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <errno.h>

#include "sl.h"
#include "config.h"

const struct sl_rule_t *sl_rules = NULL;

/**
 * match_* functions to match rule->app and /proc/PID/comm
 * @param name_from_proc
 * @param name_from_rule
 * @return true if matched, so otherwise false
 */
bool match_exact(const char *name_from_proc, const char *name_from_rule) {
    if (strcmp(name_from_proc, name_from_rule) != 0)
        return false;
    return true;
}

bool match_starts_with(const char *name_from_proc, const char *name_from_rule) {
    size_t max_len = strlen(name_from_rule);
    if (strncmp(name_from_proc, name_from_rule, max_len) != 0)
        return false;
    return true;
}

bool match_consists(const char *name_from_proc, const char *name_from_rule) {
    if (strstr(name_from_proc, name_from_rule) == NULL)
        return false;
    return true;
}

typedef bool (*match_t)(const char* proc, const char *rule);
match_t funcs[] = {
        [MATCH_EXACT] = match_exact,
        [MATCH_STARTS_WITH] = match_starts_with,
        [MATCH_CONSIST] = match_consists
};
bool to_match(const char *name_from_proc, const struct sl_rule_t* rule){
    return funcs[rule->match](name_from_proc, rule->app);
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
        // when process is closed by OS
        if (errno == ENOENT){
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
        bool ret = to_match(app_name, rule);
        if (ret) {
            printf("Found: %s\n", app_name);
            return j;
        }
    }
    return -1;
}

void sl_enum_restrict() {
    const struct sl_rule_t *rule;
    for (unsigned int i = 0; !IS_LAST_RULE(sl_rules + i); i++) {
        rule = sl_rules+i;
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

/*
 * Reload config API
 */

void update_config(struct sl_rule_t *dl_rules, size_t size){
    puts("Uploading new rules!");
    void *tmp = realloc((void *)sl_rules, size);
    if (tmp == NULL) {
        free((void *)sl_rules);
        sl_rules = NULL;
        perror("Failed realloc");
        return;
    } else {
        sl_rules = tmp;
    }

    memcpy((void *)sl_rules, dl_rules, size);
}

void reload_config(){
    int rc;
    size_t i_new, i_old = 0;
    void *handle;
    struct sl_rule_t **dl_rules_ptr, *dl_rules;

    handle = dlopen("./libconfig.so", RTLD_LAZY);
    if (handle == NULL){
        perror("Cannot load libconfig");
        abort();
    }

    dl_rules_ptr = dlsym(handle, "rules");
    if (dl_rules_ptr == NULL){
        fprintf(stderr, "Not fount 'rules': %s\n", dlerror());
        abort();
    }
    dl_rules = *dl_rules_ptr;

    // Get arrays size
    for (i_new = 0; !IS_LAST_RULE(dl_rules + i_new); ++i_new) {}
    if (sl_rules != NULL)
        for (i_old = 0; !IS_LAST_RULE(sl_rules + i_old); ++i_old) {}

    if (i_old != i_new || memcmp(dl_rules, sl_rules, sizeof(*dl_rules) * i_new) != 0)
        update_config(dl_rules, sizeof(*dl_rules) * i_new);

    rc = dlclose(handle);
    if (rc) {
        perror("Cannot unload libconfig");
        abort();
    }
}