#pragma once
#include <Lab2.h>
#include <psapi.h>
#include <tlhelp32.h>

#define LAB2_PRINTF(a, ...) {printf("\LAB2 INJECT:" a, ##__VA_ARGS__); fflush(stdout); }