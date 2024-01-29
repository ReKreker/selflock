#include <assert.h>
#include <unistd.h>

#include "sl.h"

int main() {
    // There is no way to get pid except repeatedly read /proc/
    int rc;
    while (1){
        rc = sl_enum_init();
        assert(rc > 0);
        sl_enum_restrict(rules);
        sl_enum_free();

        sleep(2);
    }
}
