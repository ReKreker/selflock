#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <errno.h>

#include "../sl.h"
#include "config.h"
#include "utils.h"
#include "match.h"
#include "zlog.h"

void sl_init_logger() {
    int rc;
    rc = zlog_init("../zlog.conf");
    if (rc) {
        printf("Logger failed");
        abort();
    }

    c = zlog_get_category("selflock");
    if (!c) {
        printf("Get cat fail\n");
        zlog_fini();
        abort();
    }

    zlog_info(c, "Selflock started!");
}

const struct sl_rule_t *sl_rules = NULL;
unsigned short sl_rules_amount = 0;

static struct {
    struct dirent **namelist;
    unsigned int amount;
} ctx;

int sl_find_app(const struct sl_rule_t *rule) {
    char app_name[64], *text_pid;
    for (int j = 0; j < ctx.amount; ++j) {
        text_pid = ctx.namelist[j]->d_name;
        sl_get_app_name(app_name, text_pid);
        bool ret = to_match(app_name, rule);
        if (ret) {
            return j;
        }
    }
    return -1;
}

void sl_enum_restrict() {
    const struct sl_rule_t *rule;
    for (unsigned int i = 0; i < sl_rules_amount; i++) {
        rule = sl_rules + i;

        // look for application for rule in list of /proc/
        int pos = sl_find_app(rule);
        if (pos == -1) continue; // restricted app didn't run or not found

        // checking
        if (sl_is_allowed(rule))
            continue;

        // killing denied
        sl_kill(ctx.namelist[pos]->d_name);
    }
}

int sl_selector(const struct dirent *d) {
    char letter;
    const char *name;
    char path[20];
    struct stat stb;

    // filter non-dir
    if (d->d_type != DT_DIR)
        return 0;

    // filter non-numeric
    name = d->d_name;
    while ((letter = *name)) {
        if (letter < '0' || '9' < letter)
            return 0;
        name++;
    }

    // filter dirs without current user creds
    snprintf(path, 20, "/proc/%s/", d->d_name);

    if (stat(path, &stb)) {
        zlog_fatal(c, "Failed stat for %s\n", path);
        abort();
    }

    if (stb.st_uid != geteuid() && stb.st_gid != getegid())
        return 0;

    return 1;
}

// There is no way to get pid except repeatedly read /proc/
int sl_enum_init() {
    if (ctx.namelist != NULL) {
        zlog_fatal(c, "Hanging pointer - internal context didn't freed or nullified");
        abort();
    }

    int res = scandir("/proc", &ctx.namelist, sl_selector, alphasort);
    if (res <= 0) {
        zlog_fatal(c, "Scandir error for /proc: %s", strerror(errno));
        abort();
    }
    ctx.amount = res;
    return res;
}

void sl_enum_free() {
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

void sl_update_config(struct sl_rule_t *dl_rules, size_t size) {
    void *tmp;

    zlog_info(c, "Uploading new rules...");
    tmp = realloc((void *) sl_rules, size);
    if (tmp == NULL) {
        free((void *) sl_rules);
        sl_rules = NULL;
        zlog_fatal(c, "Failed realloc: %s\n", strerror(errno));
        return;
    } else {
        sl_rules = tmp;
    }

    memcpy((void *) sl_rules, dl_rules, size);
}

typedef struct {
    struct sl_rule_t *rules;
    unsigned int amount;
} config_t;

int sl_dlconfig(void *handle, config_t *cfg) {
    const char *msg;
    struct sl_rule_t **dl_rules_ptr;
    unsigned int *dl_rules_amount_ptr;

    dl_rules_ptr = dlsym(handle, "rules");
    dl_rules_amount_ptr = dlsym(handle, "rules_amount");
    if (dl_rules_ptr == NULL) {
        msg = "Not fount 'rules': %s\n";
        goto error;
    }
    if (dl_rules_amount_ptr == NULL) {
        msg = "Not fount 'amount': %s\n";
        goto error;
    }
    cfg->rules = *dl_rules_ptr;
    cfg->amount = *dl_rules_amount_ptr;

    return 0;

    error:
    zlog_error(c, msg, dlerror());
    return -1;
}

void sl_try_free_dlhandle(void *handle) {
    int rc;
    if (!handle) return;

    rc = dlclose(handle);
    if (rc)
        zlog_error(c, "Cannot unload libconfig: %s", strerror(rc));
    handle = NULL;
}

void reload_config() {
    int rc;
    void *handle;
    config_t cfg;
    unsigned int rules_size;

    handle = dlopen("./libconfig.so", RTLD_LAZY);
    if (handle == NULL) {
        zlog_error(c, "Cannot load rules: %s", strerror(errno));
        if (sl_rules_amount == 0) goto fatal;
    }

    rc = sl_dlconfig(handle, &cfg);
    if (rc) {
        sl_try_free_dlhandle(handle);
        if (sl_rules_amount == 0) goto fatal;
    }

    rules_size = sizeof(*cfg.rules) * cfg.amount;
    if (sl_rules_amount != cfg.amount || memcmp(cfg.rules, sl_rules, rules_size) != 0) {
        sl_update_config(cfg.rules, rules_size);
        sl_rules_amount = cfg.amount;
    }

    sl_try_free_dlhandle(handle);
    return;

    fatal:
    zlog_fatal(c, "Fatal error while loading rules");
    abort();
}