#define MAXTOKENLENGTH 1024

typedef struct
{
	char protocol[6];
	char password[MAXTOKENLENGTH];
	char response[MAXTOKENLENGTH];
} openvpn_response;

/* Parse a string containing an openvpn response and store the result
   into an openvpn_response struct.
   If parsing succeeds result will be in result and 1 is returned.
   If parsing fails, 0 is returned, error_message is set and result remains unmodified.*/
int extract_openvpn_cr(const char *response, openvpn_response *result, char **error_message);
