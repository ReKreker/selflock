#include <assert.h>
#include <unistd.h>

#include "sl.h"

int main() {
    int rc;

    sl_init_logger();
    while (1) {
        reload_config();
        rc = sl_enum_init();
        assert(rc > 0);
        sl_enum_restrict();
        sl_enum_free();

        sleep(2);
    }
}
