/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED  AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <dh.h>
#include <string.h>
#include <syslog.h>
#define _PATH_DH_PRIMES "/etc/ssh/primes"

struct dhgroup {
	int size;
	BIGNUM *g;
	BIGNUM *p;
};
#define WHITESPACE " \t\r\n"

static DH *dh_new_group_asc(const char *gen, const char *modulus)
{
	DH *dh;
	int ret;

	dh = DH_new();
	if (dh != NULL) {
		if ((ret = BN_hex2bn(&dh->p, modulus)) < 0) {
			DH_free(dh);
			dh = NULL;
		}
		if ((ret = BN_hex2bn(&dh->g, gen)) < 0) {
			BN_free(dh->p);
			DH_free(dh);
			dh = NULL;
		}
	}
	return (dh);
}


static DH *dh_new_group(BIGNUM * gen, BIGNUM * modulus)
{
	DH *dh;

	dh = DH_new();
	if (dh != NULL) {
		dh->p = modulus;
		dh->g = gen;
	}
	return (dh);
}

static DH *dh_new_group1(void)
{
	static char *gen = "2", *group1 =
	    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B"
	    "80DC1CD1" "29024E08" "8A67CC74" "020BBEA6" "3B139B22"
	    "514A0879" "8E3404DD" "EF9519B3" "CD3A431B" "302B0A6D"
	    "F25F1437" "4FE1356D" "6D51C245" "E485B576" "625E7EC6"
	    "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED" "EE386BFB"
	    "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE65381"
	    "FFFFFFFF" "FFFFFFFF";

	return (dh_new_group_asc(gen, group1));
}

static char *strdelim(char **s)
{
	char *old;
	int wspace = 0;

	if (*s == NULL)
		return NULL;

	old = *s;

	*s = strpbrk(*s, WHITESPACE "=");
	if (*s == NULL)
		return (old);

	/* Allow only one '=' to be skipped */
	if (*s[0] == '=')
		wspace = 1;
	*s[0] = '\0';

	*s += strspn(*s + 1, WHITESPACE) + 1;
	if (*s[0] == '=' && !wspace)
		*s += strspn(*s + 1, WHITESPACE) + 1;

	return (old);
}


static int parse_prime(int linenum, char *line, struct dhgroup *dhg)
{
	char *cp, *arg;
	char *strsize, *gen, *prime;

	cp = line;
	arg = strdelim(&cp);
	/* Ignore leading whitespace */
	if (*arg == '\0')
		arg = strdelim(&cp);
	if (!*arg || *arg == '#')
		return 0;

	/* time */
	if (cp == NULL || *arg == '\0')
		goto fail;
	arg = strsep(&cp, " ");	/* type */
	if (cp == NULL || *arg == '\0')
		goto fail;
	arg = strsep(&cp, " ");	/* tests */
	if (cp == NULL || *arg == '\0')
		goto fail;
	arg = strsep(&cp, " ");	/* tries */
	if (cp == NULL || *arg == '\0')
		goto fail;
	strsize = strsep(&cp, " ");	/* size */
	if (cp == NULL || *strsize == '\0'
	    || (dhg->size = atoi(strsize)) == 0)
		goto fail;
	gen = strsep(&cp, " ");	/* gen */
	if (cp == NULL || *gen == '\0')
		goto fail;
	prime = strsep(&cp, " ");	/* prime */
	if (cp != NULL || *prime == '\0')
		goto fail;

	dhg->g = BN_new();
	if (BN_hex2bn(&dhg->g, gen) < 0) {
		BN_free(dhg->g);
		goto fail;
	}
	dhg->p = BN_new();
	if (BN_hex2bn(&dhg->p, prime) < 0) {
		BN_free(dhg->g);
		BN_free(dhg->p);
		goto fail;
	}

	return (1);
      fail:
	error("Bad prime description in line %d", linenum);
	return (0);
}




DH *choose_dh(int minbits)
{
	FILE *f;
	char line[1024];
	int best, bestcount, which;
	int linenum;
	struct dhgroup dhg;

	f = fopen(_PATH_DH_PRIMES, "r");
	if (!f) {
		syslog(LOG_INFO,
		       "WARNING: %s does not exist, using old prime",
		       _PATH_DH_PRIMES);
		return (dh_new_group1());
	}

	linenum = 0;
	best = bestcount = 0;
	while (fgets(line, sizeof(line), f)) {
		linenum++;
		if (!parse_prime(linenum, line, &dhg))
			continue;
		BN_free(dhg.g);
		BN_free(dhg.p);

		if ((dhg.size > minbits && dhg.size < best) ||
		    (dhg.size > best && best < minbits)) {
			best = dhg.size;
			bestcount = 0;
		}
		if (dhg.size == best)
			bestcount++;
	}
	fclose(f);

	if (bestcount == 0) {
		syslog(LOG_INFO,
		       "WARNING: no primes in %s, using old prime",
		       _PATH_DH_PRIMES);
		return (dh_new_group1());
	}

	f = fopen(_PATH_DH_PRIMES, "r");
	if (!f) {
		syslog(LOG_ERR, "WARNING: %s disappeared, giving up",
		       _PATH_DH_PRIMES);
		exit(1);
	}

	linenum = 0;
	which = random() % bestcount;
	while (fgets(line, sizeof(line), f)) {
		if (!parse_prime(linenum, line, &dhg))
			continue;
		if (dhg.size != best)
			continue;
		if (linenum++ != which) {
			BN_free(dhg.g);
			BN_free(dhg.p);
			continue;
		}
		break;
	}
	fclose(f);

	return (dh_new_group(dhg.g, dhg.p));
}
