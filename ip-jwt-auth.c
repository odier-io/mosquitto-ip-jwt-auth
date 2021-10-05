/*--------------------------------------------------------------------------------------------------------------------*/

#include <stdlib.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <l8w8jwt/base64.h>
#include <l8w8jwt/decode.h>

/*--------------------------------------------------------------------------------------------------------------------*/

#define MAX_NUMBER_OF_IPS 64

/*--------------------------------------------------------------------------------------------------------------------*/

static const char *ALLOWED_IPS[MAX_NUMBER_OF_IPS + 1] = { NULL };

/*--------------------------------------------------------------------------------------------------------------------*/

static int JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_HS512;

static const char *JWT_SECRET_KEY = "";

static const char *JWT_ISSUER = "";

static int JWT_VALIDATE_SUB = 1;

static int JWT_VALIDATE_EXP = 0;

static int JWT_VALIDATE_NBF = 0;

static int JWT_VALIDATE_IAT = 0;

/*--------------------------------------------------------------------------------------------------------------------*/

static int check_ip(const char *ips[], const char *ip)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	for(int i = 0; ips[i] != NULL; i++)
	{
		if(strcmp(ips[i], ip) == 0)
		{
			return 1;
		}
	}

	return 0;

	/*----------------------------------------------------------------------------------------------------------------*/
}

/*--------------------------------------------------------------------------------------------------------------------*/

static int check_jwt(int signing_algorithm, const char *secret_key, const char *issuer, const char *username, const char *password, int validate_sub, int validate_exp, int validate_nbf, int validate_iat)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	struct l8w8jwt_decoding_params decoding_params;

	l8w8jwt_decoding_params_init(&decoding_params);

	decoding_params.alg = signing_algorithm;

	decoding_params.jwt        = (char *) password;
	decoding_params.jwt_length = strlen(password);

	decoding_params.verification_key        = (char *) secret_key;
	decoding_params.verification_key_length = strlen(secret_key);

	if(strlen(issuer) > 0) {
		decoding_params.validate_iss = (char *)  issuer ;

	}

	if(   validate_sub   ) {
		decoding_params.validate_sub = (char *) username;
	}

	decoding_params.validate_exp = validate_exp;
	decoding_params.exp_tolerance_seconds = 60;

	decoding_params.validate_nbf = validate_nbf;
	decoding_params.nbf_tolerance_seconds = 60;

	decoding_params.validate_iat = validate_iat;
	decoding_params.iat_tolerance_seconds = 60;

	/*----------------------------------------------------------------------------------------------------------------*/

	enum l8w8jwt_validation_result validation_result;

	int decode_result = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

	return decode_result == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID;

	/*----------------------------------------------------------------------------------------------------------------*/
}

/*--------------------------------------------------------------------------------------------------------------------*/

static int auth_callback(
	int event,
	void *event_data,
	void *userdata
) {
	/*----------------------------------------------------------------------------------------------------------------*/

	struct mosquitto_evt_basic_auth *basic_auth = (struct mosquitto_evt_basic_auth *) event_data;

	/*----------------------------------------------------------------------------------------------------------------*/

	if(check_ip(ALLOWED_IPS, mosquitto_client_address(basic_auth->client)))
	{
		return MOSQ_ERR_SUCCESS;
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	if(check_jwt(JWT_SIGNING_ALGORITHM, JWT_SECRET_KEY, JWT_ISSUER, basic_auth->username, basic_auth->password, JWT_VALIDATE_SUB, JWT_VALIDATE_EXP, JWT_VALIDATE_NBF, JWT_VALIDATE_IAT))
	{
		return MOSQ_ERR_SUCCESS;
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	return MOSQ_ERR_AUTH;
}

/*--------------------------------------------------------------------------------------------------------------------*/

mosq_plugin_EXPORT int mosquitto_plugin_version(
	/*-*/ int supported_version_count,
	const int *supported_versions
) {
	int i;

	for(i = 0; i < supported_version_count; i++)
	{
		if(supported_versions[i] == 5)
		{
			return 5;
		}
	}

	return -1;
}

/*--------------------------------------------------------------------------------------------------------------------*/

static char *buff = NULL;

static mosquitto_plugin_id_t *plugin_id = NULL;

/*--------------------------------------------------------------------------------------------------------------------*/

int mosquitto_plugin_init(
	mosquitto_plugin_id_t *identifier,
	void **user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_log_printf(MOSQ_LOG_INFO, "Starting `mosquitto-ip-jwt-auth` (https://odier.io/mosquitto-ip-jwt-auth/)...");

	/*----------------------------------------------------------------------------------------------------------------*/

	for(int i = 0; i < opt_count; i++)
	{
		/**/ if(strcmp(opts[i].key, "allowed_ips") == 0)
		{
			int j = 0;

			char *word, *brkt;

			buff = strcpy(mosquitto_malloc(strlen(opts[i].value) + 1), opts[i].value);

			/**/

			for(word = strtok_r(buff, " ", &brkt);
			    j < MAX_NUMBER_OF_IPS && word != NULL;
			    word = strtok_r(NULL, " ", &brkt)
			) {
				ALLOWED_IPS[j++] = word;
			}

			ALLOWED_IPS[j++] = NULL;
		}
		else if(strcmp(opts[i].key, "jwt_signing_algorithm") == 0)
		{
			/**/ if(strcmp(opts[i].value, "HS256") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_HS256;
			}
			else if(strcmp(opts[i].value, "HS384") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_HS384;
			}
			else if(strcmp(opts[i].value, "HS512") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_HS512;
			}
			else if(strcmp(opts[i].value, "RS256") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_RS256;
			}
			else if(strcmp(opts[i].value, "RS384") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_RS384;
			}
			else if(strcmp(opts[i].value, "RS512") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_RS512;
			}
			else if(strcmp(opts[i].value, "PS256") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_PS256;
			}
			else if(strcmp(opts[i].value, "PS384") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_PS384;
			}
			else if(strcmp(opts[i].value, "PS512") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_PS512;
			}
			else if(strcmp(opts[i].value, "ES256") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_ES256;
			}
			else if(strcmp(opts[i].value, "ES384") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_ES384;
			}
			else if(strcmp(opts[i].value, "ES512") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_ES512;
			}
			else if(strcmp(opts[i].value, "ES256K") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_ES256K;
			}
			else if(strcmp(opts[i].value, "EdDSA") == 0) {
				JWT_SIGNING_ALGORITHM = L8W8JWT_ALG_ED25519;
			}
			else
			{
				mosquitto_log_printf(MOSQ_LOG_ERR, "Invalid JWT signing algorithm `%s`, will use `%s`", opts[i].value, "HS512");
			}
		}
		else if(strcmp(opts[i].key, "jwt_b64_secret_key") == 0)
		{
			JWT_SECRET_KEY = opts[i].value;
		}
		else if(strcmp(opts[i].key, "jwt_secret_key") == 0)
		{
			JWT_SECRET_KEY = opts[i].value;
		}
		else if(strcmp(opts[i].key, "jwt_issuer") == 0)
		{
			JWT_ISSUER = opts[i].value;
		}
		else if(strcmp(opts[i].key, "jwt_validate_sub") == 0)
		{
			JWT_VALIDATE_SUB = atoi(opts[i].value);
		}
		else if(strcmp(opts[i].key, "jwt_validate_exp") == 0)
		{
			JWT_VALIDATE_EXP = atoi(opts[i].value);
		}
		else if(strcmp(opts[i].key, "jwt_validate_nbf") == 0)
		{
			JWT_VALIDATE_NBF = atoi(opts[i].value);
		}
		else if(strcmp(opts[i].key, "jwt_validate_iat") == 0)
		{
			JWT_VALIDATE_IAT = atoi(opts[i].value);
		}
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_callback_register(plugin_id = identifier, MOSQ_EVT_BASIC_AUTH, auth_callback, NULL, NULL);

	/*----------------------------------------------------------------------------------------------------------------*/

	return MOSQ_ERR_SUCCESS;
}

/*--------------------------------------------------------------------------------------------------------------------*/

int mosquitto_plugin_cleanup(
/*	mosquitto_plugin_id_t *identifier,
 */	void *user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_log_printf(MOSQ_LOG_INFO, "Stopping `mosquitto-ip-jwt-auth`...");

	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_callback_unregister(plugin_id, MOSQ_EVT_BASIC_AUTH, auth_callback, NULL);

	/*----------------------------------------------------------------------------------------------------------------*/

	if(buff != NULL) mosquitto_free(buff);

	/*----------------------------------------------------------------------------------------------------------------*/

	return MOSQ_ERR_SUCCESS;
}

/*--------------------------------------------------------------------------------------------------------------------*/
