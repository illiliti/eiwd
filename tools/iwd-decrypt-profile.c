/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2022  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <getopt.h>

#include <ell/ell.h>

#include "ell/useful.h"

#include "src/storage.h"
#include "src/common.h"

static void usage(void)
{
	printf("decrypt-profile - Decrypt a network profile\n"
		"Usage:\n");
	printf("\tdecrypt-profile [--pass | --file] [OPTIONS]\n");
	printf("\n\tEither --pass or --file must be provided. The profile\n");
	printf("\tshould be supplied using --infile.\n");
	printf("\tThe --name argument must be used if the name cannot be\n");
	printf("\tinferred from the input file\n\n");
	printf("Options:\n"
		"\t-p, --pass             Password/key used to encrypt\n"
		"\t-f, --file             File containing key\n"
		"\t-s, --name             Name for associated profile (will\n"
		"\t                       be inferred from --infile if not\n"
		"\t                       provided). For non hotspot networks\n"
		"\t                       this will be the SSID.\n"
		"\t-i, --infile           Input profile\n"
		"\t-o, --outfile          Output file for decrypted profile\n"
		"\t-h, --help             Show help options\n");
	printf("\n");
}

static const struct option main_options[] = {
	{ "pass", required_argument,       NULL, 'p' },
	{ "file", required_argument,       NULL, 'f' },
	{ "infile", required_argument,     NULL, 'i' },
	{ "outfile", required_argument,    NULL, 'o' },
	{ "name", required_argument,       NULL, 'n' },
	{ "help", no_argument,             NULL, 'h' },
	{ }
};

static bool secret_from_file(const char *file)
{
	int fd;
	struct stat st;
	void *data = NULL;
	bool r;

	fd = open(file, O_RDONLY, 0);
	if (fd < 0) {
		printf("Cant open %s (%d)\n", file, fd);
		return false;
	}

	if (fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);
		return false;
	}

	data = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (data == MAP_FAILED)
		return false;

	r = storage_init(data, st.st_size);

	munmap(data, st.st_size);

	return r;
}

int main(int argc, char *argv[])
{
	const char *pass = NULL;
	const char *file = NULL;
	const char *infile = NULL;
	const char *outfile = NULL;
	const char *name = NULL;
	_auto_(l_free) char *decrypted = NULL;
	_auto_(l_settings_free) struct l_settings *settings = NULL;
	enum security sec;
	int ret = EXIT_FAILURE;
	ssize_t len = 0;
	int r;

	for (;;) {
		int opt;

		opt = getopt_long(argc, argv, "pfhion", main_options, NULL);
		if (opt < 0)
			break;

		switch (opt) {
		case 'p':
			pass = optarg;
			break;
		case 'f':
			file = optarg;
			break;
		case 'i':
			infile = optarg;
			break;
		case 'o':
			outfile = optarg;
			break;
		case 'n':
			name = optarg;
			break;
		case 'h':
			usage();
			return EXIT_SUCCESS;
		default:
			goto failed;
		}
	}

	if (!file && !pass) {
		printf("--file or --pass must be supplied\n\n");
		goto usage;
	}

	if (!infile) {
		printf("--infile must be supplied\n\n");
		goto usage;
	}

	if (!name) {
		name = storage_network_ssid_from_path(infile, &sec);
		if (!name) {
			printf("Can't get name from --infile, use --name\n\n");
			goto usage;
		}
	}

	settings = l_settings_new();

	if (!l_settings_load_from_file(settings, infile)) {
		printf("Profile is not formatted correctly\n");
		goto failed;
	}

	if (pass) {
		if (!storage_init((const uint8_t *)pass, strlen(pass)))
			goto failed;
	} else if (!secret_from_file(file))
		goto failed;

	r = __storage_decrypt(settings, name, NULL);
	if (r < 0) {
		printf("Unable to decrypt profile (%d)\n", r);
		goto failed;
	}

	decrypted = l_settings_to_data(settings, (size_t *)&len);

	if (!outfile)
		fwrite(decrypted, 1, len, stdout);
	else {
		int fd = open(outfile, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

		if (fd < 0) {
			printf("Unable to open %s (%d)\n", outfile, fd);
			goto failed;
		}

		len = write(fd, decrypted, len);

		close(fd);

		if (len < 0) {
			printf("Unable to write to %s (%zd)\n", outfile, len);
			goto failed;
		}
	}

	ret = EXIT_SUCCESS;

usage:
	if (ret != EXIT_SUCCESS)
		usage();

failed:
	return ret;
}
