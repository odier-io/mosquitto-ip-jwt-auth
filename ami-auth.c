#include <string.h>

#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

#include <l8w8jwt/decode.h>

static char *KEY = "YoUR sUpEr S3krEt 1337 HMAC kEy HeRE";

static mosquitto_plugin_id_t *mosq_pid = NULL;

static int basic_auth_callback(
	int event,
	void *event_data,
	void *userdata
) {
	struct mosquitto_evt_basic_auth *basic_auth = (struct mosquitto_evt_basic_auth *) event_data;

	const char *ip = mosquitto_client_address(basic_auth->client);

	mosquitto_log_printf(MOSQ_LOG_INFO, "IP: %s, Username: %s, Password: %s\n", ip, basic_auth->username, basic_auth->password);

	struct l8w8jwt_decoding_params params;

	l8w8jwt_decoding_params_init(&params);

	params.alg = L8W8JWT_ALG_HS512;

	params.jwt        = /*--*/(basic_auth->password);
	params.jwt_length = strlen(basic_auth->password);

	params.verification_key        = /*--*/(KEY);
	params.verification_key_length = strlen(KEY);

	params.validate_iss = /*---*/ "AMI" /*---*/;
	params.validate_sub = basic_auth->username;

	params.validate_exp = 0;
	params.exp_tolerance_seconds = 60;

	params.validate_iat = 0;
	params.iat_tolerance_seconds = 60;

	enum l8w8jwt_validation_result validation_result;

	int decode_result = l8w8jwt_decode(&params, &validation_result, NULL, NULL);

	if(decode_result == L8W8JWT_SUCCESS && validation_result == L8W8JWT_VALID)
	{
		return MOSQ_ERR_SUCCESS;
	}

	return MOSQ_ERR_AUTH;
}

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

int mosquitto_plugin_init(
	mosquitto_plugin_id_t *identifier,
	void **user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	mosq_pid = identifier;

	return mosquitto_callback_register(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL, NULL);
}

int mosquitto_plugin_cleanup(
        /*------------------------------*/
	void *user_data,
	struct mosquitto_opt *opts,
	int opt_count
) {
	/*------------------*/

	return mosquitto_callback_unregister(mosq_pid, MOSQ_EVT_BASIC_AUTH, basic_auth_callback, NULL /**/);
}

