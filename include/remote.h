
#include <types.h>
//protocol message types
enum proto_s {AUTH=1, CMD=2, REJECTED=3, DONE=4, CLOSE=5};

typedef struct {
    uint8_t type;
    uint16_t token_len;
    uint16_t data_len;
    char* token;
    char* data;
} proto_t;
