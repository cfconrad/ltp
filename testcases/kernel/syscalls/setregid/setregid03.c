// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *
 * Ported by John George
 */

/*
 * Test setregid() when executed by a non-root user.
 */

#include <pwd.h>

#include "tst_test.h"
#include "compat_tst_16.h"

static int fail = -1;
static int pass;
static gid_t neg_one = -1;

struct group nobody_gr, daemon_gr, root_gr, bin_gr;
struct passwd nobody;

/*
 * The following structure contains all test data.  Each structure in the array
 * is used for a separate test.  The tests are executed in the for loop below.
 */
struct test_data_t {
	gid_t *real_gid;
	gid_t *eff_gid;
	int *exp_ret;
	struct group *exp_real_usr;
	struct group *exp_eff_usr;
	char *test_msg;
} test_data[] = {
	{
	&daemon_gr.gr_gid, &bin_gr.gr_gid, &pass, &daemon_gr, &bin_gr,
		    "After setregid(daemon, bin),"}, {
	&neg_one, &daemon_gr.gr_gid, &pass, &daemon_gr, &daemon_gr,
		    "After setregid(-1, daemon)"}, {
	&neg_one, &bin_gr.gr_gid, &pass, &daemon_gr, &bin_gr,
		    "After setregid(-1, bin),"}, {
	&bin_gr.gr_gid, &neg_one, &pass, &bin_gr, &bin_gr,
		    "After setregid(bin, -1),"}, {
	&neg_one, &neg_one, &pass, &bin_gr, &bin_gr,
		    "After setregid(-1, -1),"}, {
	&neg_one, &bin_gr.gr_gid, &pass, &bin_gr, &bin_gr,
		    "After setregid(-1, bin),"}, {
	&bin_gr.gr_gid, &neg_one, &pass, &bin_gr, &bin_gr,
		    "After setregid(bin, -1),"}, {
	&bin_gr.gr_gid, &bin_gr.gr_gid, &pass, &bin_gr, &bin_gr,
		    "After setregid(bin, bin),"}, {
	&daemon_gr.gr_gid, &neg_one, &fail, &bin_gr, &bin_gr,
		    "After setregid(daemon, -1)"}, {
	&neg_one, &daemon_gr.gr_gid, &fail, &bin_gr, &bin_gr,
		    "After setregid(-1, daemon)"}, {
	&daemon_gr.gr_gid, &daemon_gr.gr_gid, &fail, &bin_gr, &bin_gr,
		    "After setregid(daemon, daemon)"},};


static void setup(void);
static void gid_verify(struct group *ru, struct group *eu, char *when);
static struct group get_group_fallback(const char *gr1, const char *gr2);
static struct group get_group(const char *group);

static void run(unsigned int i)
{
	struct test_data_t *tc = &test_data[i];

	/* Set the real or effective group id */
	TEST(SETREGID(*tc->real_gid, *tc->eff_gid));

	if (TST_RET == *tc->exp_ret) {
		if (TST_RET == -1) {
			if (TST_ERR != EPERM) {
				tst_res(TFAIL | TTERRNO,
					"setregid(%d, %d) did not set errno "
					"value as expected.",
					*tc->real_gid, *tc->eff_gid);
			} else {
				tst_res(TPASS,
					"setregid(%d, %d) failed as expected.",
					*tc->real_gid, *tc->eff_gid);
			}
		} else {
			tst_res(TPASS,
				"setregid(%d, %d) succeeded as expected.",
				*tc->real_gid, *tc->eff_gid);
		}
	} else {
		tst_res(TFAIL, "setregid(%d, %d) did not return as expected.",
			*tc->real_gid, *tc->eff_gid);
	}
	gid_verify(tc->exp_real_usr, tc->exp_eff_usr, tc->test_msg);
}

static void setup(void)
{
	nobody = *SAFE_GETPWNAM("nobody");

	nobody_gr = get_group_fallback("nobody", "nogroup");
	daemon_gr = get_group("daemon");
	bin_gr = get_group("bin");

	/* set the appropriate ownership values */
	SAFE_SETREGID(daemon_gr.gr_gid, bin_gr.gr_gid);
	SAFE_SETEUID(nobody.pw_uid);
}

static struct group get_group_fallback(const char *gr1, const char *gr2)
{
	struct group *junk;

	junk = SAFE_GETGRNAM_FALLBACK(gr1, gr2);
	GID16_CHECK(junk->gr_gid, setregid);
	return *junk;
}

static struct group get_group(const char *group)
{
	struct group *junk;

	junk = SAFE_GETGRNAM(group);
	GID16_CHECK(junk->gr_gid, setregid);
	return *junk;
}

static void gid_verify(struct group *rg, struct group *eg, char *when)
{
	if ((getgid() != rg->gr_gid) || (getegid() != eg->gr_gid)) {
		tst_res(TFAIL, "ERROR: %s real gid = %d; effective gid = %d",
			 when, getgid(), getegid());
		tst_res(TINFO, "Expected: real gid = %d; effective gid = %d",
			 rg->gr_gid, eg->gr_gid);
	} else {
		tst_res(TPASS, "real or effective gid was modified as expected");
	}
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(test_data),
	.needs_root = 1,
	.test = run,
	.setup = setup,
};
