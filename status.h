#ifndef LIGHTNING_STATUS_H
#define LIGHTNING_STATUS_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <stdlib.h>

/* Simple status reporting API. */
void status_setup(int fd);

/* Convenient context, frees up after every status_update/failed */
extern const void *trc;

/* Frees msg. */
void status_send(const u8 *msg);
void status_trace(const char *fmt, ...) PRINTF_FMT(1,2);
void status_failed(int code, const char *fmt, ...) PRINTF_FMT(2,3) NORETURN;

#endif /* LIGHTNING_STATUS_H */
