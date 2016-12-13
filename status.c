#include "status.h"
#include "utils.h"
#include "wire/wire_sync.h"
#include <assert.h>
#include <ccan/endian/endian.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/str/str.h>
#include <stdarg.h>

static int status_fd = -1;
const void *trc;

void status_setup(int fd)
{
	status_fd = fd;
	trc = tal_tmpctx(NULL);
}

void status_send(const u8 *p)
{
	assert(status_fd >= 0);

	if (!wire_sync_write(status_fd, p))
		err(1, "Writing out status len %zu", tal_count(p));
	tal_free(p);
}

static void status_send_with_hdr(u16 type, const void *p, size_t len)
{
	be16 be_type, be_len;

	be_type = cpu_to_be16(type);
	be_len = cpu_to_be16(len + sizeof(be_type));
	assert(status_fd >= 0);
	assert(be16_to_cpu(be_len) == len + sizeof(be_type));

	if (!write_all(status_fd, &be_len, sizeof(be_len))
	    || !write_all(status_fd, &be_type, sizeof(be_type))
	    || !write_all(status_fd, p, len))
		err(1, "Writing out status %u len %zu", type, len);
}

void status_trace(const char *fmt, ...)
{
	va_list ap;
	char *str;

	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	status_send_with_hdr(0xFFFF, str, strlen(str));
	tal_free(str);
	va_end(ap);

	/* Free up any temporary children. */
	tal_free(trc);
	trc = tal_tmpctx(NULL);
}

void status_failed(int code, const char *fmt, ...)
{
	va_list ap;
	char *str;

	assert(code < 0);
	va_start(ap, fmt);
	str = tal_vfmt(NULL, fmt, ap);
	status_send_with_hdr(code, str, strlen(str));
	va_end(ap);

	if (code > -128)
		exit(-code);
	else
		exit(1);
}
