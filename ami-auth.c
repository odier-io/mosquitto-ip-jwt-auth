/*--------------------------------------------------------------------------------------------------------------------*/

#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <l8w8jwt/decode.h>

/*--------------------------------------------------------------------------------------------------------------------*/

static mosquitto_plugin_id_t *plugin_id = NULL;

/*--------------------------------------------------------------------------------------------------------------------*/

static const char **IPS = {
	"",
	NULL,
};

/*--------------------------------------------------------------------------------------------------------------------*/

static const char *KEY = "YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";

/*--------------------------------------------------------------------------------------------------------------------*/

static int check_ip(const char **ips, const char *ip)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_log_printf(MOSQ_LOG_INFO, "Check IP: %s\n", ip);

	/*----------------------------------------------------------------------------------------------------------------*/

	for(; *ips != NULL; ips++)
	{
		if(strcmp(*ips, ip) == 0)
		{
			return 1;
		}
	}

	return 0;

	/*----------------------------------------------------------------------------------------------------------------*/
}

/*--------------------------------------------------------------------------------------------------------------------*/

static int check_jwt(const char *key, const char *issuer, const char *username, const char *password, int validate_exp, int validate_iat)
{
	/*----------------------------------------------------------------------------------------------------------------*/

	mosquitto_log_printf(MOSQ_LOG_INFO, "Check login/token: %s, %s\n", username, password);

	/*----------------------------------------------------------------------------------------------------------------*/

	struct l8w8jwt_decoding_params decoding_params;

	l8w8jwt_decoding_params_init(&decoding_params);

	decoding_params.alg = L8W8JWT_ALG_HS512;

	decoding_params.jwt        = /*--*/(password);
	decoding_params.jwt_length = strlen(password);

	decoding_params.verification_key        = /*--*/(key);
	decoding_params.verification_key_length = strlen(key);

	decoding_params.validate_iss =  issuer ;
	decoding_params.validate_sub = username;

	decoding_params.validate_exp = validate_exp;
	decoding_params.exp_tolerance_seconds = 60;

	decoding_params.validate_iat = validate_iat;
	decoding_params.iat_tolerance_seconds = 60;

	/*----------------------------------------------------------------------------------------------------------------*/

	enum l8w8jwt_validation_result validation_result;

	int decode_result = l8w8jwt_decode(&decoding_params, &validation_result, NULL, NULL);

	return decode_result == L8W8JWT_SUCCESS
	       &&
	       validation_result == L8W8JWT_VALID
	;

	/*----------------------------------------------------------------------------------------------------------------*/
}

/*--------------------------------------------------------------------------------------------------------------------*/

static int basic_auth_callback(
	int event,
	void *event_data,
	void *userdata
) {
	/*----------------------------------------------------------------------------------------------------------------*/

	struct mosquitto_evt_basic_auth *basic_auth = (struct mosquitto_evt_basic_auth *) event_data;

	/*----------------------------------------------------------------------------------------------------------------*/

	if(check_ip(IPS, mosquitto_client_address(basic_auth->client)))
	{
		return MOSQ_ERR_SUCCESS;
	}

	/*----------------------------------------------------------------------------------------------------------------*/

	if(check_jwt(KEY, "AMI", basic_auth->username, basic_auth->password, 0, 0))
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

int mosquitto_plugin_init(
	mosquitto_plugin_id_t *identifier,
	void **user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	return mosquitto_callback_register(mosq_pid = identifier, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
}

/*--------------------------------------------------------------------------------------------------------------------*/

int mosquitto_plugin_cleanup(
	void *user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	return mosquitto_callback_unregister(plugin_id = plugin_id, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL /**/);
}

/*--------------------------------------------------------------------------------------------------------------------*/
