/* ykchub.c --- A software implementation of a Yubikey hardware token
 *
 * Emulates a basic Yubikey token in HOTP mode, using the yubikey library
 *
 * Written by Arran Cudbard-Bell <a.cudbardb@freeradius.org>.
 * Copyright (c) 2022 Arran Cudbard-Bell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *    * Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "yubikey.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#  include <bsd/stdlib.h>
#endif

static bool debug = false;
static char const *prog;

#define ERROR(_fmt, ...) fprintf(stderr, _fmt "\n", ## __VA_ARGS__)
#define INFO(_fmt, ...) fprintf(stdout, _fmt "\n", ## __VA_ARGS__)
#define DEBUG(_fmt, ...) if (debug) fprintf(stderr, _fmt "\n", ## __VA_ARGS__)

typedef struct {
	yubikey_token_st	tok;				//!< Token information structure
								///< used by the yubikey library.
	uint8_t			public_id[YUBIKEY_UID_SIZE];	//!< 6 byte public identifier.
	uint8_t			aes_key[YUBIKEY_KEY_SIZE];	//!< 16 byte private AES key.
	uint32_t		ponrand;			//!< Power on rand, changes whenever
								///< the session counter wraps.
	time_t			created;			//!< When the yubikey was first "powered on"
	time_t			lastuse;			//!< When the yubikey was last used.
} yksoft_t;

#define nbo_48(_bin) \
	(((uint64_t)_bin[0] << 40) | \
	((uint64_t)_bin[1] << 32) | \
	((uint64_t)_bin[2] << 24) | \
	((uint64_t)_bin[3] << 16) | \
	((uint64_t)_bin[4] << 8) | \
	_bin[5])

int persistent_file_write(char const *path, yksoft_t const *in)
{
	char		public_id_modhex[(sizeof(in->public_id) * 2) + 1];
	char		private_id_hex[(sizeof(in->tok.uid) * 2) + 1];
	char		aes_key_hex[(sizeof(in->aes_key) * 2) + 1];
	FILE		*persist;
	fpos_t		pos;

	umask(S_IRWXG | S_IRWXO);

	if (!(persist = fopen(path, "w"))) {
		ERROR("Failed opening persistance file: %s", strerror(errno));
		return -1;
	}

	if (flock(fileno(persist), LOCK_EX) < 0) {
		ERROR("Failed locking persistence file: %s", strerror(errno));
	close:
		fclose(persist);
		return -1;
	}

	yubikey_modhex_encode(public_id_modhex, (char const *)in->public_id, sizeof(in->public_id));
	yubikey_hex_encode(private_id_hex, (char const *)in->tok.uid, sizeof(in->tok.uid));
	yubikey_hex_encode(aes_key_hex, (char const *)in->aes_key, sizeof(in->aes_key));

#define WRITE(_fmt, ...) \
do { \
	fprintf(persist, _fmt "\n", ##__VA_ARGS__); \
	DEBUG(_fmt, ##__VA_ARGS__); \
} while(0)

	DEBUG("Persisting data to \"%s\"", path);
	DEBUG("===");
	WRITE("public_id: %s", public_id_modhex);
	WRITE("private_id: %s", private_id_hex);
	WRITE("aes_key: %s", aes_key_hex);
	WRITE("counter: %u", in->tok.ctr);
	WRITE("session: %u", in->tok.use);
	WRITE("created: %" PRIu64, (uint64_t)in->created);
	WRITE("lastuse: %" PRIu64, (uint64_t)in->lastuse);
	WRITE("ponrand: %u", in->ponrand);
	DEBUG("");

	fgetpos(persist, &pos);

#ifdef __linux__
	if (ftruncate(fileno(persist), pos.__pos) < 0) {
#else
	if (ftruncate(fileno(persist), pos) < 0) {
#endif
		ERROR("Failed truncating persistence file: %s", strerror(errno));
		goto close;
	}
	fclose(persist);	/* Releases the lock too */

	return 0;
}

/** Writes out a persistant file containing key information
 *
 */
int persistent_data_generate(yksoft_t *out,
			     uint8_t const public_id[YUBIKEY_UID_SIZE],
			     uint8_t const private_id[YUBIKEY_UID_SIZE],
			     uint8_t const aes_key[YUBIKEY_KEY_SIZE],
			     uint32_t counter)
{
	uint64_t	hztime;

	if (!public_id) {
		struct { uint16_t a; uint32_t b; } __attribute__((packed)) rid;

		rid.a = 0x2222;	/* dddd in modhex */
		rid.b = arc4random();

		memcpy(out->public_id, (uint8_t *)&rid, sizeof(out->public_id));
	} else {
		memcpy(out->public_id, public_id, sizeof(out->public_id));
	}

	if (!private_id) {
		arc4random_buf(out->tok.uid, sizeof(out->tok.uid));
	} else {
		memcpy(out->tok.uid, private_id, sizeof(out->tok.uid));
	}

	if (!aes_key) {
		arc4random_buf(out->aes_key, sizeof(out->aes_key));
	} else {
		memcpy(out->aes_key, aes_key, sizeof(out->aes_key));
	}

	out->tok.ctr = counter + 1;			/* First "power up" */
	out->tok.use = 1;				/* First "session" */

	out->lastuse = out->created = time(NULL);	/* Record the token creation time */
	out->ponrand = arc4random() & 0xfffffff0;		/* Fudge the time, so not all tokens are synced to time() */

	hztime = out->ponrand;
	hztime %= 0xffffff;	/* 24bit wrap */

	out->tok.tstpl = hztime & 0xffff;
	out->tok.tstph = (hztime >> 16) & 0xff;
	out->tok.rnd = arc4random();

	return 0;
}

int persistent_data_update(yksoft_t *out)
{
	time_t		now = time(NULL);
	uint64_t	hztime;

	/*
	 *	Too many session uses, increment the
	 *	main counter.
	 */
	if (out->tok.use == 0xff) {
		DEBUG("Session counter wrapped");

		/*
		 *	Token is dead if counter can't be incremented
		 */
		if (++out->tok.ctr == 0x7fff) {
			ERROR("Token counter at max, token must be regenerated");
			return -1;
		}
		out->ponrand = arc4random();	/* We don't *really* need to regenerate this, but whatever */
		out->tok.use = 1;		/* Reset session use counter */
	} else {
		out->tok.use++;			/* Increment the session counter */
	}

	/*
	 *	We go to great lengths to be lazy and not
	 *	have to figure out the high precision
	 *	time functions for the platform.
	 */
again:
	if (now == out->lastuse) {
		if ((out->ponrand & 0x0000000f) > 6) {		/* Rate limit generations */
			DEBUG("Waiting for 1 second before generating new token");
			sleep(1);
			now = time(NULL);
			out->ponrand &= 0xfffffff0;		/* Clear 8hz nibble */
			goto again;
		} else {
			out->ponrand++;
		}
	} else {
		out->lastuse = now;				/* Last used is now */
		out->ponrand &= 0xfffffff0;			/* Clear 8hz nibble */
	}

	/*
	 *	Figure out what 8hz time is...
	 */
	hztime = (now - out->created) * 8;
	hztime += out->ponrand;
	hztime %= 0xffffff;	/* 24bit wrap */

	out->tok.tstpl = hztime & 0xffff;
	out->tok.tstph = (hztime >> 16) & 0xff;
	out->tok.rnd = arc4random();

	return 0;
}

int persistent_data_load(yksoft_t *out, char const *path)
{
	FILE			*persist;
	char			buff[256];
	char			key[12];
	unsigned long long	num;

	if (!(persist = fopen(path, "r"))) {
		ERROR("Failed opening persistance file: %s", strerror(errno));
		return -1;
	}

	if (flock(fileno(persist), LOCK_EX) < 0) {
		ERROR("Failed locking persistence file: %s", strerror(errno));
	error:
		fclose(persist);
		return -1;
	}

	DEBUG("Reading persisted data from \"%s\"", path);
	DEBUG("===");

	while (fgets(buff, sizeof(buff), persist)) {
		char const	*end_p;
		char const	*p;
		char		*nl;
		char		*num_end;

		if (!(p = strchr(buff, ':'))) {
			ERROR("Invalid line: %s", buff);
			goto error;
		}

		if ((p - buff) > (sizeof(key) - 1)) {
			ERROR("Key too long: %s", buff);
			goto error;
		}

		strncpy(key, buff, p - buff);
		key[p - buff] = '\0';

		p++;				/* Skip the parator */
		while (isspace(*p)) p++;	/* skip whitespace */
		end_p = p + strlen(p);

		/*
		 *	Trim trailing newline
		 */
		if ((nl = strchr(p, '\n'))) {
			*nl = '\0';
			end_p = nl;
		}

		/*
		 *	Match the key
		 */
		if (strcmp(key, "public_id") == 0) {
			if (strlen(p) != (sizeof(out->public_id) * 2)) {
				ERROR("Invalid size for \"public_id\", expected %zu, got %zu (%s)",
				      (sizeof(out->tok.uid) * 2), strlen(p), p);
				goto error;
			}
			yubikey_modhex_decode((char *)out->public_id, p, sizeof(out->public_id));

			DEBUG("public_id: %s", p);
		} else if (strcmp(key, "private_id") == 0) {
			if (strlen(p) != (sizeof(out->tok.uid) * 2)) {
				ERROR("Invalid size for \"private_id\", expected %zu, got %zu (%s)",
				      (sizeof(out->tok.uid) * 2), strlen(p), p);
				goto error;
			}
			yubikey_hex_decode((char *)out->tok.uid, p, sizeof(out->tok.uid));

			DEBUG("private_id: %s", p);
		} else if (strcmp(key, "aes_key") == 0) {
			if (strlen(p) != (sizeof(out->aes_key) * 2)) {
				ERROR("Invalid size for \"aes_key\", expected %zu, got %zu (%s)",
				      (sizeof(out->aes_key) * 2), strlen(p), p);
				goto error;
			}
			yubikey_hex_decode((char *)out->aes_key, p, sizeof(out->aes_key));

			DEBUG("aes_key: %s", p);
		} else if (strcmp(key, "counter") == 0) {
			num = strtoull(p, &num_end, 10);
			if ((num_end != end_p) || (num > 0x7ffff)) {
				ERROR("Invalid counter value");
				goto error;
			}
			out->tok.ctr = (uint16_t)num;

			DEBUG("counter: %u", out->tok.ctr);
		} else if (strcmp(key, "session") == 0) {
			num = strtoull(p, &num_end, 10);
			if ((num_end != end_p) || (num > 0xff)) {
				ERROR("Invalid session value");
				goto error;
			}
			out->tok.use = (uint8_t)num;

			DEBUG("session: %u", out->tok.use);
		} else if (strcmp(key, "created") == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid created value");
				goto error;
			}
			out->created = (time_t)num;

			DEBUG("created: %" PRIu64, (uint64_t)out->created);
		/*
		 *	When the token was last used
		 */
		} else if (strcmp(key, "lastuse") == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid lastuse value");
				goto error;
			}
			out->lastuse = (time_t)num;
			if (out->lastuse > time(NULL)) {
				ERROR("lastuse time travel detected, refusing to generated token for %"PRIu64"s",
				      (uint64_t)(out->lastuse - num));
				goto error;
			}

			DEBUG("lastuse: %" PRIu64, (uint64_t)out->lastuse);
		/*
		 *	Random number from last time the token
		 *	was "powered on"
		 */
		} else if (strcmp(key, "ponrand") == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid ponrand value");
				goto error;
			}
			out->ponrand = num;

			DEBUG("ponrand: %u", out->ponrand);
		}
	}
	if (((errno = ferror(persist)) != 0) || (feof(persist) == 0)) {
		ERROR("Failed reading from \"%s\": %s", path, strerror(errno));
		goto error;
	}
	fclose(persist);
	DEBUG("");

	return 0;
}
static __attribute__((noreturn)) void usage(int ret)
{
	INFO("usage: %s [options] <token file>\n", prog);
	INFO("  -I <public_id>   Public ID as MODHEX to use for initialisation (max 6 bytes i.e. 12 modhexits).");
	INFO("                   If the Public ID is < 6 bytes, the remaining bytes will be randomised.");
	INFO("                   Defaults to dddd<4 byte random>.");
	INFO("  -i <private_id>  Private ID as HEX to use for initialisation (6 bytes i.e. 12 hexits).");
	INFO("                   Defaults to <6 byte random>.");
	INFO("  -k <key>         AES key as HEX to use for initialisation (16 bytes i.e. 32 hexits).");
	INFO("                   Defaults to <16 byte random>.");
	INFO("  -c <counter>     Counter for initialisation (0-32766).  Will always be incremented by one on first use.");
	INFO("                   Defaults to 0.");
	INFO("  -r               Prints out registration information to stderr.");
	INFO("  -h               This help text.");
	INFO("");
	INFO("Emulate a hardware yubikey token in HOTP mode.");
	exit(ret);
}

#define EXIT_WITH_FAILURE exit(EXIT_FAILURE)
#define EXIT_WITH_SUCCESS exit(EXIT_SUCCESS)

int main(int argc, char *argv[])
{
	yksoft_t	yksoft;
	char		otp[(YUBIKEY_UID_SIZE * 2) + YUBIKEY_OTP_SIZE + 1];
	char const	*file;
  	char		c;
  	struct stat	pstat;

  	/*
  	 *	Initialisation values
  	 */
  	uint32_t	counter = 0;
  	bool		got_counter = false;
  	uint8_t		public_id[YUBIKEY_UID_SIZE];
  	bool		got_public_id = false;
    	size_t		public_id_len;
	uint8_t		private_id[YUBIKEY_UID_SIZE];
	bool		got_private_id = false;
	uint8_t		aes_key[YUBIKEY_KEY_SIZE];
	bool		got_aes_key = false;
	bool		show_registration_info = false;

	prog = argv[0];

	memset(&yksoft, 0, sizeof(yksoft));

	while ((c = getopt(argc, argv, "I:i:k:c:drh")) != -1) switch (c) {
		/* Public ID */
		case 'I':
		{
			size_t arglen = strlen(optarg);

			if (arglen > (sizeof(public_id) * 2)) {
				ERROR("Invalid argument: -I should be less than %zu modhexits, got %zu modhexits",
				      sizeof(public_id) * 2, arglen);
				usage(64);
			}
			if (arglen & 0x01) {
				ERROR("Invalid argument: -I should be an even number of modhexits");
				usage(64);
			}
			yubikey_modhex_decode((char *)public_id, (char *)optarg, sizeof(public_id));
			public_id_len = arglen / 2;

			/*
			 *	Allow prefixes to be specified for the public id
			 */
			if (public_id_len < sizeof(public_id)) {
				arc4random_buf(public_id + public_id_len, sizeof(public_id) - public_id_len);
			}
			got_public_id = true;
		}
			break;

		/* Private ID */
		case 'i':
			if (strlen(optarg) != (sizeof(private_id) * 2)) {
				ERROR("Invalid argument: -i should be exactly %zu hexits, got %zu hexits",
				      sizeof(private_id) * 2, strlen(optarg));
				usage(64);
			}
			yubikey_hex_decode((char *)private_id, (char *)optarg, sizeof(private_id));
			got_private_id = true;
			break;

		case 'k':
			if (strlen(optarg) != (sizeof(aes_key) * 2)) {
				ERROR("Invalid argument: -k should be exactly %zu hexits, got %zu hexits",
				      sizeof(aes_key) * 2, strlen(optarg));
				usage(64);
			}
			yubikey_hex_decode((char *)aes_key, (char *)optarg, sizeof(aes_key));
			got_aes_key = true;
			break;

		case 'c':
			counter = strtol((char *)optarg, NULL, 0);
			got_counter = true;
			break;

		case 'd':
			debug = true;
			break;

		case 'r':
			show_registration_info = true;
			break;

		case 'h':
		default:
			usage(EXIT_SUCCESS);
			break;
	}
	argc -= optind;
	argv += optind;

	if (argc == 0) {
		ERROR("Need persistence file to operate on");
		usage(64);
	};
	file = argv[0];

	if (stat(file, &pstat) == 0) {
		if (pstat.st_mode & (S_IROTH | S_IWOTH)) {
			ERROR("Persistence file must NOT be world readable or world writable,  "
			      "`chmod o-wr %s`.", file);
			EXIT_WITH_FAILURE;
		}

		if (persistent_data_load(&yksoft, file) < 0) EXIT_WITH_FAILURE;
		if (persistent_data_update(&yksoft) < 0) EXIT_WITH_FAILURE;

		if (got_public_id) {
			if (memcmp(public_id, yksoft.public_id, public_id_len) != 0) {
				ERROR("Invalid argument: Provided public_id does not match persisted public_id, remove -I");
				EXIT_WITH_FAILURE;
			}
		}

		if (got_private_id) {
			if (memcmp(private_id, yksoft.tok.uid, sizeof(private_id)) != 0) {
				ERROR("Invalid argument: Provided private_id does not match persisted private_id, remove -i");
				EXIT_WITH_FAILURE;
			}
		}

		if (got_aes_key) {
			if (memcmp(aes_key, yksoft.aes_key, sizeof(aes_key)) != 0) {
				ERROR("Invalid argument: Provided key does not match persisted aes key, remove -k");
				EXIT_WITH_FAILURE;
			}
		}

		if (got_counter) {
			if (counter < yksoft.tok.ctr) {
				ERROR("Invalid argument: Provided counter < persisted counter, remove -c");
				EXIT_WITH_FAILURE;
			}
			yksoft.tok.ctr = counter;
		}

		if (!show_registration_info && (persistent_file_write(file, &yksoft) < 0)) EXIT_WITH_FAILURE;
	} else {
		if (persistent_data_generate(&yksoft,
					     got_public_id ? public_id : NULL,
					     got_private_id ? private_id : NULL,
					     got_aes_key ? aes_key : NULL,
					     counter) < 0) EXIT_WITH_FAILURE;

		/*
		 *	New token, print out the identifier and aes_key
		 */
		show_registration_info = true;
		if (persistent_file_write(file, &yksoft) < 0) EXIT_WITH_FAILURE;
	}

	if (show_registration_info) {
		char	public_id_modhex[(sizeof(yksoft.public_id) * 2) + 1];
		char	public_id_hex[(sizeof(yksoft.public_id) * 2) + 1];
		char	private_id_hex[(sizeof(yksoft.tok.uid) * 2) + 1];
		char	private_id_modhex[(sizeof(yksoft.tok.uid) * 2) + 1];
		char	aes_key_hex[(sizeof(yksoft.aes_key) * 2) + 1];

		yubikey_modhex_encode(public_id_modhex, (char const *)yksoft.public_id, sizeof(yksoft.public_id));
		yubikey_modhex_encode(private_id_modhex, (char const *)yksoft.tok.uid, sizeof(yksoft.tok.uid));
		yubikey_hex_encode(public_id_hex, (char const *)yksoft.public_id, sizeof(yksoft.public_id));
		yubikey_hex_encode(private_id_hex, (char const *)yksoft.tok.uid, sizeof(yksoft.tok.uid));
		yubikey_hex_encode(aes_key_hex, (char const *)yksoft.aes_key, sizeof(yksoft.aes_key));

		DEBUG("Registration information");
		DEBUG("===");
		INFO("public_id_modhex: %s", public_id_modhex);
		INFO("public_id_hex: %s", public_id_hex);
		INFO("public_id_dec: %" PRIu64, nbo_48(yksoft.public_id));
		INFO("private_id_modhex: %s", private_id_modhex);
		INFO("private_id_hex: %s", private_id_hex);
		INFO("private_id_dec: %" PRIu64, nbo_48(yksoft.tok.uid));
		INFO("aes_key_hex: %s", aes_key_hex);
		DEBUG("");

		EXIT_WITH_SUCCESS;
	}

	yksoft.tok.crc = ~yubikey_crc16((void *)&yksoft.tok, sizeof(yksoft.tok) - sizeof(yksoft.tok.crc));

	DEBUG("Generated data");
	DEBUG("===");
	DEBUG("timestamp: %u, low %u (0x%x), high %u (0x%x)",
	      (uint32_t)(yksoft.tok.tstpl | (yksoft.tok.tstph << 16)),
	      yksoft.tok.tstpl, yksoft.tok.tstpl,
	      yksoft.tok.tstph, yksoft.tok.tstph);
	DEBUG("random: %u (0x%x)", yksoft.tok.rnd, yksoft.tok.rnd);
	DEBUG("crc: %u (0x%x)", yksoft.tok.crc, yksoft.tok.crc);
	DEBUG("");

	yubikey_modhex_encode(otp, (char const *)yksoft.public_id, sizeof(yksoft.public_id));
	yubikey_generate((void *)&yksoft.tok, yksoft.aes_key, otp + (YUBIKEY_UID_SIZE * 2));

	DEBUG("OTP token");
	DEBUG("===");
  	fprintf(stdout, "%s\n", otp);

	EXIT_WITH_SUCCESS;
}
