/* yksoft.c --- A software implementation of a Yubikey hardware token
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

#define PUBLIC_ID_FIELD		"public_id"
#define PRIVATE_ID_FIELD	"private_id"
#define AES_KEY_FIELD		"aes_key"
#define COUNTER_FIELD		"counter"
#define SESSION_FIELD		"session"
#define CREATED_FIELD		"created"
#define LASTUSE_FIELD		"lastuse"
#define PONRAND_FIELD		"ponrand"

#define EXIT_WITH_FAILURE exit(EXIT_FAILURE)
#define EXIT_WITH_SUCCESS exit(EXIT_SUCCESS)

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

int persistent_file_write(int token_dir_fd, char const *token_dir, char const *path, yksoft_t const *in)
{
	FILE		*persist;
	int		persist_fd;

	char		public_id_modhex[(sizeof(in->public_id) * 2) + 1];
	char		private_id_hex[(sizeof(in->tok.uid) * 2) + 1];
	char		aes_key_hex[(sizeof(in->aes_key) * 2) + 1];

	fpos_t		pos;

	umask(S_IRWXG | S_IRWXO);

	persist_fd = openat(token_dir_fd, path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (persist_fd < 0) {
	open_failed:
		ERROR("Failed opening persistance file \"%s/%s\": %s", token_dir, path, strerror(errno));
		return -1;
	}

	if (!(persist = fdopen(persist_fd, "w"))) {
		close(persist_fd);
		goto open_failed;
	}

	if (flock(persist_fd, LOCK_EX) < 0) {
		ERROR("Failed locking persistence file \"%s/%s\": %s", token_dir, path, strerror(errno));
	error:
		fclose(persist);
		close(persist_fd);
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

	DEBUG("Persisting data to \"%s/%s\"", token_dir, path);
	DEBUG("===");
	WRITE(PUBLIC_ID_FIELD ": %s", public_id_modhex);
	WRITE(PRIVATE_ID_FIELD ": %s", private_id_hex);
	WRITE(AES_KEY_FIELD ": %s", aes_key_hex);
	WRITE(COUNTER_FIELD ": %u", in->tok.ctr);
	WRITE(SESSION_FIELD ": %u", in->tok.use);
	WRITE(CREATED_FIELD ": %" PRIu64, (uint64_t)in->created);
	WRITE(LASTUSE_FIELD ": %" PRIu64, (uint64_t)in->lastuse);
	WRITE(PONRAND_FIELD ": %u", in->ponrand);
	DEBUG("");

	fgetpos(persist, &pos);

#ifdef __linux__
	if (ftruncate(fileno(persist), pos.__pos) < 0) {
#else
	if (ftruncate(fileno(persist), pos) < 0) {
#endif
		ERROR("Failed truncating persistence file \"%s/%s\": %s", token_dir, path, strerror(errno));
		goto error;
	}
	fclose(persist);	/* Releases the lock too */
	close(persist_fd);

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
	out->ponrand = arc4random() & 0xfffffff0;	/* Fudge the time, so not all tokens are synced to time() */

	hztime = out->ponrand;
	hztime %= 0xffffff;	/* 24bit wrap */

	out->tok.tstpl = hztime & 0xffff;
	out->tok.tstph = (hztime >> 16) & 0xff;
	out->tok.rnd = arc4random();

	return 0;
}

int persistent_data_exec(yksoft_t *in, char const *cmd)
{
	char public_id[sizeof(PUBLIC_ID_FIELD) + 1 + (sizeof(in->public_id) * 2)];
	char private_id[sizeof(PRIVATE_ID_FIELD) + 1 + (sizeof(in->tok.uid) * 2)];
	char aes_key[sizeof(AES_KEY_FIELD) + 1 + (sizeof(in->aes_key) * 2)];
	char counter[sizeof(COUNTER_FIELD) + 1 + (sizeof("65535") - 1)];
	char session[sizeof(SESSION_FIELD) + 1 + (sizeof("255") - 1)];
	char created[sizeof(CREATED_FIELD) + 1 + (sizeof("18446744073709551615") - 1)];
	char lastuse[sizeof(LASTUSE_FIELD) + 1 + (sizeof("18446744073709551615") - 1)];
	char ponrand[sizeof(PONRAND_FIELD) + 1 + (sizeof("4294967295") - 1)];

	char public_id_modhex[(sizeof(in->public_id) * 2) + 1];
	char private_id_hex[(sizeof(in->tok.uid) * 2) + 1];
	char aes_key_hex[(sizeof(in->aes_key) * 2) + 1];

	yubikey_modhex_encode(public_id_modhex, (char const *)in->public_id, sizeof(in->public_id));
	yubikey_hex_encode(private_id_hex, (char const *)in->tok.uid, sizeof(in->tok.uid));
	yubikey_hex_encode(aes_key_hex, (char const *)in->aes_key, sizeof(in->aes_key));

	char const * argv[] = {
			"-c",
			cmd,
			NULL
		};
	char *envp[] = {
			public_id,
			private_id,
			aes_key,
			counter,
			session,
			created,
			lastuse,
			ponrand,
			NULL
		};
	int status;
	pid_t pid;
	char const *sh_path = "/bin/sh";

	if (getenv("SHELL")) sh_path = getenv("SHELL");

	DEBUG("Calling \"%s\" to persist token information", cmd);

#define SET_ENV(_buff, _fmt, ...) \
do { \
	snprintf(_buff, sizeof(_buff), _fmt, __VA_ARGS__); \
	DEBUG("%s", _buff); \
} while (0)

	SET_ENV(public_id, PUBLIC_ID_FIELD "=%s", public_id_modhex);
	SET_ENV(private_id, PRIVATE_ID_FIELD "=%s", private_id_hex);
	SET_ENV(aes_key, AES_KEY_FIELD "=%s", aes_key_hex);
	SET_ENV(counter, COUNTER_FIELD "=%u", in->tok.ctr);
	SET_ENV(session, SESSION_FIELD "=%u", in->tok.use);
	SET_ENV(created, CREATED_FIELD "=%" PRIu64, (uint64_t)in->created);
	SET_ENV(lastuse, LASTUSE_FIELD "=%" PRIu64, (uint64_t)in->lastuse);
	SET_ENV(ponrand, PONRAND_FIELD "=%u", in->ponrand);

	pid = fork();
	if (pid < 0) {
		ERROR("Failed forking persistence command \"%s\"", strerror(errno));
		return -1;
	} else if (pid == 0) { /* child */
		if (execve(sh_path, (char **)((intptr_t)argv), envp) < 0) {      /* never returns on success */
			ERROR("Failed executing persistence command \"%s\": %s", cmd, strerror(errno));
			EXIT_WITH_FAILURE;
		}
	}

	/* parent */
	if (waitpid(pid, &status, 0) < 0) {
		ERROR("Failed waiting for persistence command: %s", strerror(errno));
		return -1;
	}

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) == 0) { /* success */
			DEBUG("Persistence command succeeded");
		} else {
			ERROR("Persistence command failed: %u", WIFEXITED(status));
			return -1;
		}
	} else {
		ERROR("Persistence command exited abnormally: %i", status);
		return -1;
	}

	return 0;
}

int persistent_data_update(yksoft_t *out)
{
	time_t		now = time(NULL);
	uint64_t	hztime;
	int	     ret = 0;

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
		ret = 1;			/* Tell the caller we wrapped */
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

	return ret;
}

int persistent_data_load(yksoft_t *out, int token_dir_fd, char const *token_dir, char const *path)
{
	int			persist_fd;
	FILE			*persist;
	char			buff[256];
	char			key[12];
	unsigned long long	num;

	persist_fd = openat(token_dir_fd, path, O_RDONLY);
	if (persist_fd < 0) {
	open_failed:
		ERROR("Failed opening persistance file \"%s/%s\": %s", token_dir, path, strerror(errno));
		return -1;
	}

	if (!(persist = fdopen(persist_fd, "r"))) goto open_failed;

	if (flock(persist_fd, LOCK_EX) < 0) {
		ERROR("Failed locking persistence file \"%s/%s\": %s", token_dir, path, strerror(errno));
	error:
		close(persist_fd);
		fclose(persist);
		return -1;
	}

	DEBUG("Reading persisted data from \"%s/%s\"", token_dir, path);
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
		if (strcmp(key, PUBLIC_ID_FIELD) == 0) {
			if (strlen(p) != (sizeof(out->public_id) * 2)) {
				ERROR("Invalid size for \"" PUBLIC_ID_FIELD "\", expected %zu, got %zu (%s)",
				      (sizeof(out->tok.uid) * 2), strlen(p), p);
				goto error;
			}
			yubikey_modhex_decode((char *)out->public_id, p, sizeof(out->public_id));

			DEBUG(PUBLIC_ID_FIELD ": %s", p);
		} else if (strcmp(key, PRIVATE_ID_FIELD) == 0) {
			if (strlen(p) != (sizeof(out->tok.uid) * 2)) {
				ERROR("Invalid size for \"" PRIVATE_ID_FIELD "\", expected %zu, got %zu (%s)",
				      (sizeof(out->tok.uid) * 2), strlen(p), p);
				goto error;
			}
			yubikey_hex_decode((char *)out->tok.uid, p, sizeof(out->tok.uid));

			DEBUG(PRIVATE_ID_FIELD ": %s", p);
		} else if (strcmp(key, AES_KEY_FIELD) == 0) {
			if (strlen(p) != (sizeof(out->aes_key) * 2)) {
				ERROR("Invalid size for \"" AES_KEY_FIELD "\", expected %zu, got %zu (%s)",
				      (sizeof(out->aes_key) * 2), strlen(p), p);
				goto error;
			}
			yubikey_hex_decode((char *)out->aes_key, p, sizeof(out->aes_key));

			DEBUG(AES_KEY_FIELD ": %s", p);
		} else if (strcmp(key, COUNTER_FIELD) == 0) {
			num = strtoull(p, &num_end, 10);
			if ((num_end != end_p) || (num > 0x7ffff)) {
				ERROR("Invalid " COUNTER_FIELD " value");
				goto error;
			}
			out->tok.ctr = (uint16_t)num;

			DEBUG(COUNTER_FIELD ": %u", out->tok.ctr);
		} else if (strcmp(key, SESSION_FIELD) == 0) {
			num = strtoull(p, &num_end, 10);
			if ((num_end != end_p) || (num > 0xff)) {
				ERROR("Invalid " SESSION_FIELD " value");
				goto error;
			}
			out->tok.use = (uint8_t)num;

			DEBUG(SESSION_FIELD ": %u", out->tok.use);
		} else if (strcmp(key, CREATED_FIELD) == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid " CREATED_FIELD " value");
				goto error;
			}
			out->created = (time_t)num;

			DEBUG(CREATED_FIELD ": %" PRIu64, (uint64_t)out->created);
		/*
		 *	When the token was last used
		 */
		} else if (strcmp(key, LASTUSE_FIELD) == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid " LASTUSE_FIELD " value");
				goto error;
			}
			out->lastuse = (time_t)num;
			if (out->lastuse > time(NULL)) {
				ERROR(LASTUSE_FIELD " time travel detected, refusing to generated token for %"PRIu64"s",
				      (uint64_t)(out->lastuse - num));
				goto error;
			}

			DEBUG(LASTUSE_FIELD ": %" PRIu64, (uint64_t)out->lastuse);
		/*
		 *	Random number from last time the token
		 *	was "powered on"
		 */
		} else if (strcmp(key, PONRAND_FIELD) == 0) {
			num = strtoull(p, &num_end, 10);
			if (num_end != end_p) {
				ERROR("Invalid " PONRAND_FIELD " value");
				goto error;
			}
			out->ponrand = num;

			DEBUG(PONRAND_FIELD ": %u", out->ponrand);
		}
	}
	if (((errno = ferror(persist)) != 0) || (feof(persist) == 0)) {
		ERROR("Failed reading from \"%s/%s\": %s", token_dir, path, strerror(errno));
		goto error;
	}
	fclose(persist);
	close(persist_fd);
	DEBUG("");

	return 0;
}
static __attribute__((noreturn)) void usage(int ret)
{
	INFO("usage: %s [options] [<token file>]\n", prog);
	INFO("  -C <counter_cmd>        Run a persistence command when a new token is generated, or when the 'use' counter increments.");
	INFO("");
	INFO("  -c <counter>            Counter for initialisation (0-32766).  Will always be incremented by one on first use.  Defaults to 0.");
	INFO("");
	INFO("  -I <public_id>          Public ID as MODHEX to use for initialisation (max 6 bytes i.e. 12 modhexits).  Defaults to dddd<4 byte random>.");
	INFO("                          If the Public ID is < 6 bytes, the remaining bytes will be randomised.");
	INFO("");
	INFO("  -i <private_id>         Private ID as HEX to use for initialisation (6 bytes i.e. 12 hexits).  Defaults to 6 bytes of random data.");
	INFO("");
	INFO("  -k <key>                AES key as HEX to use for initialisation (16 bytes i.e. 32 hexits).  Defaults to 16 bytes of random data.");
	INFO("");
	INFO("  -d                      Turns on debug logging to stderr.");
	INFO("");
	INFO("  -f                      Specify the directory tokens are stored in.  Defaults to \"~/.%s\"", prog);
	INFO("  -f		      Specify the directory tokens are stored in.  Defaults to \"~/.%s\"", prog);
	INFO("");
	INFO("  -r                      Prints out registration information to stdout. An OTP will not be generated.");
	INFO("");
	INFO("  -R                      Regenerate the specified token.");
	INFO("");
	INFO("  -h                      This help text.");
	INFO("");
	INFO("Emulate a hardware yubikey token in HOTP mode.");
	exit(ret);
}

int main(int argc, char *argv[])
{
	yksoft_t	yksoft;
	char		otp[(YUBIKEY_UID_SIZE * 2) + YUBIKEY_OTP_SIZE + 1];
	char const	*file;
  	char		c;
  	struct stat	pstat;
  	char const	*token_dir = NULL;
  	char		token_dir_exp[PATH_MAX + 1];

	int		dir_fd = -1;

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
	bool		regenerate = false;

	char const      *counter_cmd = NULL;

	prog = strrchr(argv[0], '/');
	if (prog) {
		prog++;
	} else {
		prog = argv[0];
	}

	memset(&yksoft, 0, sizeof(yksoft));

	while ((c = getopt(argc, argv, "c:C:df:I:i:k:rRh")) != -1) switch (c) {
		case 'c':
			counter = strtol((char *)optarg, NULL, 0);
			got_counter = true;
			break;

		case 'C':
			counter_cmd = optarg;
			break;

		case 'd':
			debug = true;
			break;

		case 'f':
			token_dir = optarg;
			break;

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


		case 'r':
			show_registration_info = true;
			break;

		case 'R':
			regenerate = true;
			break;

		case 'h':
		default:
			usage(EXIT_SUCCESS);
			break;
	}
	argc -= optind;
	argv += optind;

	/*
	 *	Default to "default" for the token name
	 */
	file = argv[0];
	if (!file) file = "default";

	/*
	 *	By default our default dir is relative
	 *	to the home directory of the user...
	 */
	if (!token_dir) {
		snprintf(token_dir_exp, sizeof(token_dir_exp), "%s/.%s", getenv("HOME"), prog);
		token_dir = token_dir_exp;
	}

	dir_fd = open(token_dir, O_RDONLY | O_DIRECTORY);
	if (dir_fd < 0) {
		if (errno != ENOENT) {
			ERROR("Cannot open token directory \"%s\": %s", token_dir, strerror(errno));
			EXIT_WITH_FAILURE;
		}
		dir_fd = mkdir(token_dir, S_IRWXU);
		if (dir_fd < 0) {
			ERROR("Cannot create token directory \"%s\": %s", token_dir, strerror(errno));
			EXIT_WITH_FAILURE;
		}

		dir_fd = open(token_dir, O_RDONLY | O_DIRECTORY);
		if (dir_fd < 0) {
			ERROR("Failed opening the token directory we just created \"%s\": %s",
			      token_dir, strerror(errno));
			EXIT_WITH_FAILURE;
		}
	}

	if (!regenerate && (fstatat(dir_fd, file, &pstat, 0) == 0)) {
		if (pstat.st_mode & (S_IROTH | S_IWOTH)) {
			ERROR("Persistence file must NOT be world readable or world writable,  "
			      "`chmod o-wr %s`.", file);
			EXIT_WITH_FAILURE;
		}

		if (persistent_data_load(&yksoft, dir_fd, token_dir, file) < 0) EXIT_WITH_FAILURE;

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

		if (!show_registration_info) {
			int ret = persistent_data_update(&yksoft);

			switch (ret) {
			case -1:
				EXIT_WITH_FAILURE;

			/*
			 *      ctr was incremented, tell someone...
			 */
			case 1:
				if (!counter_cmd) break;
				if (persistent_data_exec(&yksoft, counter_cmd) < 0) EXIT_WITH_FAILURE;
				break;

			case 0:
				break;
			}
			if (persistent_file_write(dir_fd, token_dir, file, &yksoft) < 0) EXIT_WITH_FAILURE;
		}
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
		if (counter_cmd && persistent_data_exec(&yksoft, counter_cmd) < 0) EXIT_WITH_FAILURE;
		if (persistent_file_write(dir_fd, token_dir, file, &yksoft) < 0) EXIT_WITH_FAILURE;
	}

	if (show_registration_info) {
		char	public_id_modhex[(sizeof(yksoft.public_id) * 2) + 1];
		char	public_id_hex[(sizeof(yksoft.public_id) * 2) + 1];
		char	private_id_hex[(sizeof(yksoft.tok.uid) * 2) + 1];
		char	private_id_modhex[(sizeof(yksoft.tok.uid) * 2) + 1];
		char	aes_key_hex[(sizeof(yksoft.aes_key) * 2) + 1];

		yubikey_modhex_encode(public_id_modhex, (char const *)yksoft.public_id, sizeof(yksoft.public_id));
		if (debug) yubikey_modhex_encode(private_id_modhex, (char const *)yksoft.tok.uid, sizeof(yksoft.tok.uid));
		if (debug) yubikey_hex_encode(public_id_hex, (char const *)yksoft.public_id, sizeof(yksoft.public_id));
		yubikey_hex_encode(private_id_hex, (char const *)yksoft.tok.uid, sizeof(yksoft.tok.uid));
		yubikey_hex_encode(aes_key_hex, (char const *)yksoft.aes_key, sizeof(yksoft.aes_key));

		DEBUG("Registration information");
		DEBUG("===");
		DEBUG(PUBLIC_ID_FIELD "_modhex: %s", public_id_modhex);
		DEBUG(PUBLIC_ID_FIELD "_hex: %s", public_id_hex);
		DEBUG(PUBLIC_ID_FIELD "_dec: %" PRIu64, nbo_48(yksoft.public_id));
		DEBUG(PRIVATE_ID_FIELD "_modhex: %s", private_id_modhex);
		DEBUG(PRIVATE_ID_FIELD "_hex: %s", private_id_hex);
		DEBUG(PRIVATE_ID_FIELD "_dec: %" PRIu64, nbo_48(yksoft.tok.uid));
		DEBUG(AES_KEY_FIELD "_hex: %s", aes_key_hex);
		INFO("%s, %s, %s", public_id_modhex, private_id_hex, aes_key_hex);
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
  	INFO("%s", otp);

	EXIT_WITH_SUCCESS;
}
