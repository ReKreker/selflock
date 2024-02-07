#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/dir.h>
#include <stdbool.h>
#include <dlfcn.h>

#include "../sl.h"
#include "config.h"
#include "utils.h"
#include "match.h"

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
    puts("--------------------------");
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
        printf("Failed stat for %s\n", path);
        abort();
    }

    if (stb.st_uid != geteuid() && stb.st_gid != getegid())
        return 0;

    return 1;
}

int sl_enum_init() {
    if (ctx.namelist != NULL) {
        puts("Hanging pointer - internal context didn't freed and nullified");
        abort();
    }

    int res = scandir("/proc", &ctx.namelist, sl_selector, alphasort);
    if (res <= 0) {
        puts("Scandir error for /proc\n");
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

void update_config(struct sl_rule_t *dl_rules, size_t size) {
    puts("Uploading new rules!");
    void *tmp = realloc((void *) sl_rules, size);
    if (tmp == NULL) {
        free((void *) sl_rules);
        sl_rules = NULL;
        perror("Failed realloc");
        return;
    } else {
        sl_rules = tmp;
    }

    memcpy((void *) sl_rules, dl_rules, size);
}

void reload_config() {
    int rc;
    void *handle;
    struct sl_rule_t **dl_rules_ptr, *dl_rules;
    unsigned int *dl_rules_amount_ptr, dl_rules_amount;

    handle = dlopen("./libconfig.so", RTLD_LAZY);
    if (handle == NULL) {
        perror("Cannot load libconfig");
        abort();
    }

    dl_rules_ptr = dlsym(handle, "rules");
    dl_rules_amount_ptr = dlsym(handle, "rules_amount");
    if (dl_rules_ptr == NULL || dl_rules_amount_ptr == NULL) {
        fprintf(stderr, "Not fount 'rules'/'rules_amount': %s\n", dlerror());
        abort();
    }
    dl_rules = *dl_rules_ptr;
    dl_rules_amount = *dl_rules_amount_ptr;

    if (sl_rules_amount != dl_rules_amount
        || memcmp(dl_rules, sl_rules, sizeof(*dl_rules) * dl_rules_amount) != 0) {
        update_config(dl_rules, sizeof(*dl_rules) * dl_rules_amount);
        sl_rules_amount = dl_rules_amount;
    }

    rc = dlclose(handle);
    if (rc) {
        perror("Cannot unload libconfig");
        abort();
    }
}