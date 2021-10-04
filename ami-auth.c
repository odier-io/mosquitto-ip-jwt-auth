/*--------------------------------------------------------------------------------------------------------------------*/

#include <stdlib.h>
#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <l8w8jwt/decode.h>

/*--------------------------------------------------------------------------------------------------------------------*/

static const char *ALLOWED_IPS[64] = { NULL };

/*--------------------------------------------------------------------------------------------------------------------*/

static const char *JWT_SECRET_KEY = "E7F66F88_9DC9_8697_17DD_E292BFFBEE16";

static const char *JWT_ISSUER = "D51D9082_2BB3_B3F8_7FC4_6275B034A09D";

static int JWT_VALIDATE_EXP = 0;

static int JWT_VALIDATE_IAT = 0;

/*--------------------------------------------------------------------------------------------------------------------*/

static int check_ip(const char *ips[], const char *ip)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	for(int i = 0; i < 64 && ips[i] != NULL; i++)
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

static int check_jwt(const char *secret_key, const char *issuer, const char *username, const char *password, int validate_exp, int validate_iat)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	struct l8w8jwt_decoding_params decoding_params;

	l8w8jwt_decoding_params_init(&decoding_params);

	decoding_params.alg = L8W8JWT_ALG_HS512;

	decoding_params.jwt        = (char *) password;
	decoding_params.jwt_length = strlen(password);

	decoding_params.verification_key        = (char *) secret_key;
	decoding_params.verification_key_length = strlen(secret_key);

	decoding_params.validate_iss = (char *)  issuer ;
	decoding_params.validate_sub = (char *) username;

	decoding_params.validate_exp = validate_exp;
	decoding_params.exp_tolerance_seconds = 60;

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

	if(check_jwt(JWT_SECRET_KEY, JWT_ISSUER, basic_auth->username, basic_auth->password, JWT_VALIDATE_EXP, JWT_VALIDATE_IAT))
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

	mosquitto_log_printf(MOSQ_LOG_INFO, "Using `mosquitto-ami-auth` :D");

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
			    j < 64 && word != NULL;
			    word = strtok_r(NULL, " ", &brkt)
			) {
				ALLOWED_IPS[j++] = word;
			}

			ALLOWED_IPS[j++] = NULL;
		}
		else if(strcmp(opts[i].key, "jwt_secret_key") == 0)
		{
			JWT_SECRET_KEY = opts[i].value;
		}
		else if(strcmp(opts[i].key, "jwt_issuer") == 0)
		{
			JWT_ISSUER = opts[i].value;
		}
		else if(strcmp(opts[i].key, "jwt_validate_exp") == 0)
		{
			JWT_VALIDATE_EXP = atoi(opts[i].value);
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

	mosquitto_callback_unregister(/*--*/ plugin_id /*--*/, MOSQ_EVT_BASIC_AUTH, auth_callback, NULL /**/);

	/*----------------------------------------------------------------------------------------------------------------*/

	if(buff != NULL) mosquitto_free(buff);

	/*----------------------------------------------------------------------------------------------------------------*/

	return MOSQ_ERR_SUCCESS;
}

/*--------------------------------------------------------------------------------------------------------------------*/
