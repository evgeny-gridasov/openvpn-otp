#include "openvpn-cr.h"

#include "base64.h"
#include <string.h>

static const char * static_cr_label = "SCRV1";
static const char * dynamic_cr_label = "CRV1";

int set_token_b64(const char * source, char * destination)
{
	if (Base64decode_len(source) >= MAXTOKENLENGTH)
		return 0;
	Base64decode(destination, source); 
	return 1;
}

int set_token(const char * source, char * destination)
{
	if (strlen(source) >= MAXTOKENLENGTH)
		return 0;
	strncpy(destination, source, MAXTOKENLENGTH);
	return 1;
}


int extract_openvpn_cr(const char *response, openvpn_response *result, char **error_message)
{
	const char *tokenIndexes[15];
	tokenIndexes[0] = response;
	int tokenCnt = 1;
	const char *p;
	for (p = response; *p; ++p) {
		if (*p == ':')
			tokenIndexes[tokenCnt++] = p + 1;
	}

	if (tokenCnt == 3 && strstr(response, static_cr_label) == response)
	{
		if (!set_token(static_cr_label, result->protocol)){
			*error_message = "Unable to set static protocol information.";
			return 0;
		}

		if (!set_token_b64(tokenIndexes[1], result->password)) {
			*error_message = "Unable to extract password from static cr.";
			return 0;
		}

		if (!set_token_b64(tokenIndexes[2], result->response)) {
			*error_message = "Unable to extract response from static cr.";
			return 0;
		}
	}
	else if (tokenCnt == 5 && strstr(response, dynamic_cr_label) == response) {
		if (!set_token(dynamic_cr_label, result->protocol)) {
			*error_message = "Unable to set dynamic protocol information.";
			return 0;
		}

		if (!set_token_b64(tokenIndexes[2], result->password)) {
			*error_message = "Unable to extract password from dynamic cr.";
			return 0;
		}

		if (!set_token_b64(tokenIndexes[4], result->response)) {
			*error_message = "Unable to extract response from dynamic cr.";
			return 0;
		}
	}
	else {
		*error_message = "Incorrectly formatted cr string.";
		return 0;
	}
	return 1;
}


