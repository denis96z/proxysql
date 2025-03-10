
#include "PgSQL_Variables_Validator.h"
#include "PgSQL_Session.h"
#include "cpp.h"

/**
 * @brief Validates a boolean variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid boolean representation
 * and transforms it if necessary. The valid representations for false are "0", "f", "false", and "off".
 * The valid representations for true are "1", "t", "true", and "on".
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the transformed value ("on" for false inputs, "off" for true inputs).
 * @return true if the value is a valid boolean representation, false otherwise.
 */
bool pgsql_variable_validate_bool(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
    (void)params;
    (void)session;
    bool result = false;
    if (transformed_value) *transformed_value = nullptr;
    if (
        (strcasecmp(value, (char*)"0") == 0) ||
        (strcasecmp(value, (char*)"f") == 0) ||
        (strcasecmp(value, (char*)"false") == 0) ||
        (strcasecmp(value, (char*)"off") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("off");
        result = true;
    } else if (
        (strcasecmp(value, (char*)"1") == 0) ||
        (strcasecmp(value, (char*)"t") == 0) ||
        (strcasecmp(value, (char*)"true") == 0) ||
        (strcasecmp(value, (char*)"on") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("on");
        result = true;
    }
    return result;
}

/**
* @brief Validates an integer variable for PostgreSQL.
*
* This function checks if the provided value is a valid integer representation
* and falls within the specified range. The range is defined by the params
* parameter.
*
* @param value The value to validate.
* @param params The parameter structure containing the integer range.
* @param session Unused parameter.
* @param transformed_value If not null, will be set to null.
* @return true if the value is a valid integer representation within the specified range, false otherwise.
*/
bool pgsql_variable_validate_integer(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
   (void)session;
   if (transformed_value) *transformed_value = nullptr;
   char* end = nullptr;
   long num = strtol(value, &end, 10);
   if (end == value || *end != '\0') return false;
   if (num < params->int_range.min || num > params->int_range.max) return false;
   return true;
}

/**
 * @brief Validates a string variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid string representation
 * based on the allowed strings specified in the params parameter.
 *
 * @param value The value to validate.
 * @param params The parameter structure containing the allowed strings.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the validated value.
 * @return true if the value is a valid string representation, false otherwise.
 */
bool pgsql_variable_validate_string(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
    (void)session;
    if (transformed_value) *transformed_value = nullptr;
    if (params->string_allowed) {
        const char** allowed_ptr = params->string_allowed;
        while (*allowed_ptr) {
            if (strcasecmp(value, *allowed_ptr) == 0) {
                if (transformed_value)
                    *transformed_value = strdup(*allowed_ptr);
                return true;
            }
            allowed_ptr++;
        }
    }
    return false;
}

/**
 * @brief Validates a DateStyle variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid DateStyle representation.
 * If the session is null, it parses the DateStyle value directly. If the session is not null,
 * it uses the current DateStyle from the session to fill in any missing parts of the provided value.
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session The current session, which holds the current DateStyle.
 * @param transformed_value If not null, will be set to the transformed value.
 * @return true if the value is a valid DateStyle representation, false otherwise.
 */
bool pgsql_variable_validate_datestyle(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	if (transformed_value) *transformed_value = nullptr;

	if (session == nullptr) {
		PgSQL_DateStyle_t datestyle = PgSQL_DateStyle_Util::parse_datestyle(value);
		if (datestyle.format == DATESTYLE_FORMAT_NONE || datestyle.order == DATESTYLE_ORDER_NONE) {
			return false;
		}

		if (transformed_value) {
			PgSQL_DateStyle_t current_datestyle = { .format = DATESTYLE_FORMAT_NONE, .order = DATESTYLE_ORDER_NONE };
			const std::string& value_tmp = PgSQL_DateStyle_Util::datestyle_to_string(value, current_datestyle);
			// if something goes wrong, the value will be empty
			if (value_tmp.empty()) {
				return false;
			}

			*transformed_value = strdup(value_tmp.c_str());
		}
		return true;
	}

	const PgSQL_DateStyle_t& current_datestyle = session->current_datestyle;
	assert(current_datestyle.format != DATESTYLE_FORMAT_NONE);
	assert(current_datestyle.order != DATESTYLE_ORDER_NONE);

	// Especial case:
	// PostgreSQL strangely accepts an empty value for datestyle, but it does not alter previously set value.
	if (strlen(value) == 0) {
		if (transformed_value) *transformed_value = strdup("");
		return true;
	}
	//------------------------------------------------------------------------------------------------------

	// Convert DateStyle to a string. Any missing parts will be filled using the current DateStyle value.
	// For example:
	// If current DateStyle is 'ISO, MDY' and the user sets 'DMY' the resulting DateStyle will be 'ISO, DMY'
	const std::string& value_tmp = PgSQL_DateStyle_Util::datestyle_to_string(value, current_datestyle);
	// if something goes wrong, the value will be empty
	if (value_tmp.empty()) {
		return false;
	}
	if (transformed_value)
		*transformed_value = strdup(value_tmp.c_str());
	return true;
}

/**
 * @brief Validates the maintenance_work_mem variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid representation of memory size
 * with optional units. The valid units are 'kB', 'MB', 'GB', and 'TB'. If no unit is
 * specified, 'kB' is assumed by default. The function also normalizes the value to
 * always include the unit in lowercase.
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the normalized value.
 * @return true if the value is a valid memory size representation, false otherwise.
 */
bool pgsql_variable_validate_maintenance_work_mem(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	(void)session;
	const char* p = value;
	char* endptr;
	long long num;
	char unit = 'k';  // Default unit is 'k' (kB)
	bool has_unit = false;
	
	if (transformed_value) *transformed_value = nullptr;

	// Skip leading whitespace
	while (isspace((unsigned char)*p)) p++;

	// Parse numeric part
	num = strtoll(p, &endptr, 10);
	if (p == endptr || num <= 0) return false;

	if (errno == ERANGE && (num == LLONG_MAX || num == LLONG_MIN)) {
		return false;
	}

	p = endptr;

	// Skip whitespace after number
	while (isspace((unsigned char)*p)) p++;

	// Parse unit
	if (*p != '\0') {
		switch (tolower(*p)) {
		case 'k': case 'm': case 'g': case 't':
			unit = tolower(*p++);
			has_unit = true;
			// Check optional 'b'/'B'
			if (tolower(*p) == 'b') p++;
			break;
		default:
			return false;
		}
	}

	// Skip trailing whitespace
	while (isspace((unsigned char)*p)) p++;

	// Validate entire string consumed
	if (*p != '\0') return false;

	char output[128];
	// Format normalized string (always show unit in lowercase)
	int written = snprintf(output, sizeof(output), has_unit ? "%lld%cb" : "%lldkb",
		num, unit);

	if (written < 0 || written >= (int)sizeof(output)) return false;

	if (transformed_value)
		*transformed_value = strdup(output);

	return true;
}

const pgsql_variable_validator pgsql_variable_validator_bool = {
	.type = VARIABLE_TYPE_BOOL,
	.validate = &pgsql_variable_validate_bool,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_extra_float_digits = {
	.type = VARIABLE_TYPE_INT,
	.validate = &pgsql_variable_validate_integer,
	.params = {
		.int_range = { .min = -15, .max = 3 }
	}
};

const pgsql_variable_validator pgsql_variable_validator_intervalstyle = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "postgres", "sql_standard", "sql_iso", "sql_invariant", nullptr } 
	}
};

const pgsql_variable_validator pgsql_variable_validator_synchronous_commit = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = { 
		.string_allowed = (const char* []){ "local", "remote_write", "remote_apply", "on", "off", nullptr } 
	}
};

const pgsql_variable_validator pgsql_variable_validator_client_min_messages = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "debug5", "debug4", "debug3", "debug2", "debug1", "log", "notice", "warning", "error", nullptr }
	}
};

const pgsql_variable_validator pgsql_variable_validator_bytea_output = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "hex", "escape", nullptr }
	}
};

const pgsql_variable_validator pgsql_variable_validator_datestyle = {
	.type = VARIABLE_TYPE_DATESTYLE,
	.validate = &pgsql_variable_validate_datestyle,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_maintenance_work_mem = {
	.type = VARIABLE_TYPE_MAINTENANCE_WORK_MEM,
	.validate = &pgsql_variable_validate_maintenance_work_mem,
	.params = {}
};
