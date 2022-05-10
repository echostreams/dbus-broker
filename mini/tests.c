#include "log.h"

void test_setup_logging(int level) {
    log_set_max_level(level);
    //log_parse_environment();
    //log_open();
}