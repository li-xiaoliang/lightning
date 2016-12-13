#include <assert.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <ccan/err/err.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/structeq/structeq.h>
#include "status.h"

/* Since we use pipes, we need different fds for read and write. */
static int read_fd, write_fd;

static bool fake_read_all(int fd, void *buf, size_t count)
{
	return read_all(read_fd, buf, count);
}

static ssize_t fake_write_all(int fd, const void *buf, size_t count)
{
	return write_all(write_fd, buf, count);
}

static const char *status_prefix;

/* Simply print out status updates. */
#define status_send(msg) \
	printf("%s:%u\n", status_prefix, fromwire_peektype(msg))
#define status_failed(code, fmt, ...)	\
	errx(1, "%s:%s:" fmt "\n", status_prefix, #code, __VA_ARGS__)
#define status_trace(fmt, ...) \
	printf("%s:" fmt "\n", status_prefix, __VA_ARGS__)

#define read_all fake_read_all
#define write_all fake_write_all

/* No randomness please, we want to replicate test vectors. */
#include <sodium/randombytes.h>

static unsigned char e_priv[32];
#define randombytes_buf(secret, len) memcpy((secret), e_priv, len)

#define TESTING
#include "../handshake.c"
#include "utils.h"
#include <ccan/err/err.h>

secp256k1_context *secp256k1_ctx;
const void *trc;
static struct privkey privkey;

void hsm_setup(int fd)
{
}

bool hsm_do_ecdh(struct sha256 *ss, const struct pubkey *point)
{
	return secp256k1_ecdh(secp256k1_ctx, ss->u.u8, &point->pubkey,
			      privkey.secret) == 1;
}

char *type_to_string_(const tal_t *ctx,  const char *typename,
		      union printable_types u)
{
	assert(streq(typename, "struct pubkey"));
	return pubkey_to_hexstr(ctx, u.pubkey);
}

int main(void)
{
	struct crypto_complete *cc;
	int fds1[2], fds2[2];
	struct pubkey responder_id;
	struct privkey responder_privkey;
	const tal_t *ctx = tal_tmpctx(NULL);

	trc = tal_tmpctx(ctx);

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);

	memset(responder_privkey.secret, 0x21,
	       sizeof(responder_privkey.secret));
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&responder_id.pubkey,
					responder_privkey.secret))
		errx(1, "Keygen failed");

	if (pipe(fds1) != 0 || pipe(fds2) != 0)
		err(1, "Making pipes");

	switch (fork()) {
	case -1:
		err(1, "fork failed");
	case 0: {
		struct pubkey their_id;

		memset(e_priv, 0x22, sizeof(e_priv));
		read_fd = fds1[0];
		write_fd = fds2[1];
		close(fds1[1]);
		close(fds2[0]);
		privkey = responder_privkey;
		status_prefix = "RESPR";
		status_trace("ls.priv=%s",
			     tal_hexstr(trc, responder_privkey.secret,
					sizeof(responder_privkey)));
		status_trace("ls.pub=%s",
			     type_to_string(trc, struct pubkey, &responder_id));
		cc = responder(ctx, -1, &responder_id, &their_id);
		if (!cc)
			errx(1, "responder failed");
		if (!write_all(write_fd, cc, sizeof(*cc)))
			err(1, "writing out cc failed");
		goto out;
	}
	default: {
		struct pubkey initiator_id;
		struct privkey initiator_privkey;
		struct crypto_complete their_cc;

		read_fd = fds2[0];
		write_fd = fds1[1];
		close(fds2[1]);
		close(fds1[0]);

		memset(initiator_privkey.secret, 0x11,
		       sizeof(initiator_privkey.secret));
		memset(e_priv, 0x12, sizeof(e_priv));
		if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
						&initiator_id.pubkey,
						initiator_privkey.secret))
			errx(1, "Initiator keygen failed");
		privkey = initiator_privkey;
		status_prefix = "INITR";
		status_trace("ls.priv=%s",
			     tal_hexstr(trc, initiator_privkey.secret,
					sizeof(initiator_privkey)));
		status_trace("ls.pub=%s",
			     type_to_string(trc, struct pubkey, &initiator_id));
		status_trace("rs.pub=%s",
			     type_to_string(trc, struct pubkey, &responder_id));

		cc = initiator(ctx, -1, &initiator_id, &responder_id);
		if (!cc)
			errx(1, "connection_out failed");
		if (!read_all(read_fd, &their_cc, sizeof(their_cc)))
			err(1, "reading their cc failed");

		assert(structeq(&cc->ck, &their_cc.ck));
		assert(structeq(&cc->sk, &their_cc.rk));
		assert(structeq(&cc->rk, &their_cc.sk));
		goto out;
	}
	}

out:
	/* No memory leaks please */
	secp256k1_context_destroy(secp256k1_ctx);
	tal_free(ctx);
	return 0;
}
