/* Minimal replacement for the HCTR2 repository's testvec.h / util.h. */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

struct testvec_buffer {
	size_t len;
	const uint8_t *data;
};
