#include "Inject.h"

void usage()
{
	printf("\nLAB2Inject.exe <target_proc>...");
}

int main(int argc, char ** argv)
{
	if (argc < 2)
	{
		usage();
		return 1;
	}
	LAB2_PRINTF("Starting ... ");
	return 0;
} 