
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
        (strcasecmp(value, (char*)"off") == 0) ||
		(strcasecmp(value, (char*)"no") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("off");
        result = true;
    } else if (
        (strcasecmp(value, (char*)"1") == 0) ||
        (strcasecmp(value, (char*)"t") == 0) ||
        (strcasecmp(value, (char*)"true") == 0) ||
        (strcasecmp(value, (char*)"on") == 0) ||
		(strcasecmp(value, (char*)"yes") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("on");
        result = true;
    }
    return result;
}

/**
* @brief Validates an float variable for PostgreSQL.
*
* This function checks if the provided value is a valid float representation
* and falls within the specified range. The range is defined by the params
* parameter.
*
* @param value The value to validate.
* @param params The parameter structure containing the float range.
* @param session Unused parameter.
* @param transformed_value If not null, will be set to null.
* @return true if the value is a valid float representation within the specified range, false otherwise.
*/
bool pgsql_variable_validate_float(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
   (void)session;
   if (transformed_value) *transformed_value = nullptr;
   char* end = nullptr;
   //long num = strtol(value, &end, 10);
   double num = strtod(value, &end);  
   if (end == value || *end != '\0') return false;
   if (num < params->float_range.min || num > params->float_range.max) return false;
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
		char tmp_unit = tolower(*p);
		switch (tmp_unit) {
		case 'k': 
		case 'm': 
		case 'g': 
		case 't':
			if (tmp_unit != 'k')
				unit = toupper(*p++);
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
	int written = snprintf(output, sizeof(output), has_unit ? "%lld%cB" : "%lldkB",
		num, unit);

	if (written < 0 || written >= (int)sizeof(output)) return false;

	if (transformed_value)
		*transformed_value = strdup(output);

	return true;
}

bool pgsql_variable_validate_maintenance_work_mem_v2(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)session;
	const char* input = value;

	/* Trim leading whitespace */
	while (isspace((unsigned char)*input)) input++;

	/* Parse numeric part */
	uint64_t number;
	char* endptr;
	//size_t num_len = 0;
	errno = 0;
	number = strtoull(input, &endptr, 10);

	if (endptr == input || errno == ERANGE || number == 0)
		return false;

	//num_len = endptr - input;

	// Skip whitespace after number
	while (isspace((unsigned char)*endptr)) endptr++;

	/* Parse unit part */
	const char* unit_ptr = endptr;
	uint64_t multiplier;
	char unit[3] = { 0 };
	size_t unit_len = strlen(unit_ptr);

	/* Handle default unit (kB) if no unit specified */
	if (unit_len == 0) {
		strcpy(unit, "kB");
		multiplier = 1024;
	}
	else {
		/* Convert unit to lowercase for validation */
		char u[3] = { 0 };
		for (int i = 0; i < 2 && unit_ptr[i]; i++)
			u[i] = tolower((unsigned char)unit_ptr[i]);

		/* Validate unit and set multiplier */
		if (unit_len == 1 && u[0] == 'b') {
			strcpy(unit, "B");
			multiplier = 1;
		}
		else if (strcmp(u, "kb") == 0) {
			strcpy(unit, "kB");
			multiplier = 1024;
		}
		else if (strcmp(u, "mb") == 0) {
			strcpy(unit, "MB");
			multiplier = 1024 * 1024;
		}
		else if (strcmp(u, "gb") == 0) {
			strcpy(unit, "GB");
			multiplier = 1024ULL * 1024 * 1024;
		}
		else if (strcmp(u, "tb") == 0) {
			strcpy(unit, "TB");
			multiplier = 1024ULL * 1024 * 1024 * 1024;
		}
		else {
			return false;
		}

		/* Validate unit length matches parsed characters */
		size_t actual_unit_len = (unit[1] == 'B') ? 2 : (unit[0] == 'B') ? 1 : 0;
		if (strlen(unit_ptr) != actual_unit_len)
			return false;
	}

	/* Check for multiplication overflow */
	if (number > UINT64_MAX / multiplier)
		return false;

	uint64_t total_bytes = number * multiplier;

	/* Validate PostgreSQL's requirements */
	if ((total_bytes / 1024ULL) < params->uint_range.min || (total_bytes / 1024ULL) > params->uint_range.max)
		return false;

	char output[128];
	/* Format output without leading zeros */
	int needed = snprintf(output, sizeof(output), "%lu%s", number, unit);

	if (needed < 0 || needed >= (int)sizeof(output)) return false;

	if (transformed_value)
		*transformed_value = strdup(output);

	return true;
}

bool pgsql_variable_validate_maintenance_work_mem_v3(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)session;

	// Trim leading whitespace
	while (isspace((unsigned char)*value)) value++;

	char* endptr;
	const char* num_start = value;
	errno = 0;
	double number = strtod(value, &endptr);

	// Basic numeric validation
	if (endptr == num_start || errno == ERANGE || number <= 0)
		return false;

	// Validate numeric format (digits and single decimal point)
	int dot_count = 0;
	const char* p = num_start;
	while (p < endptr) {
		if (*p == '.') {
			if (++dot_count > 1) return false;
		}
		else if (!isdigit((unsigned char)*p)) {
			return false;
		}
		p++;
	}

	// Parse unit
	const char* unit_ptr = endptr;
	uint64_t multiplier;
	char unit[3] = { 0 };
	size_t unit_len = strlen(unit_ptr);

	// Default to kB if no unit specified
	if (unit_len == 0) {
		strcpy(unit, "kB");
		multiplier = 1024;
	}
	else {
		// Convert unit to lowercase for validation
		char u[3] = { 0 };
		for (int i = 0; i < 2 && unit_ptr[i]; i++)
			u[i] = tolower((unsigned char)unit_ptr[i]);

		// Validate units and set multipliers
		if (unit_len == 1 && u[0] == 'b') {
			strcpy(unit, "B");
			multiplier = 1;
		}
		else if (strcmp(u, "kb") == 0) {
			strcpy(unit, "kB");
			multiplier = 1024;
		}
		else if (strcmp(u, "mb") == 0) {
			strcpy(unit, "MB");
			multiplier = 1024 * 1024;
		}
		else if (strcmp(u, "gb") == 0) {
			strcpy(unit, "GB");
			multiplier = 1024ULL * 1024 * 1024;
		}
		else if (strcmp(u, "tb") == 0) {
			strcpy(unit, "TB");
			multiplier = 1024ULL * 1024 * 1024 * 1024;
		}
		else {
			return false;
		}

		// Validate unit length matches parsed characters
		size_t expected_len = (unit[1] == 'B') ? 2 : (unit[0] == 'B') ? 1 : 0;
		if (strlen(unit_ptr) != expected_len)
			return false;
	}

	// Calculate total bytes with floating point
	uint64_t total_bytes = (uint64_t)number * multiplier;

	/* Validate PostgreSQL's requirements */
	if ((total_bytes / 1024ULL) < params->uint_range.min || (total_bytes / 1024ULL) > params->uint_range.max)
		return false;

	char output[128];
	/* Format output without leading zeros */
	int needed = snprintf(output, sizeof(output), "%.15g%s", number, unit);

	if (needed < 0 || needed >= (int)sizeof(output)) return false;

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
	.type = VARIABLE_TYPE_FLOAT,
	.validate = &pgsql_variable_validate_float,
	.params = {
		.float_range = { .min = -15.0, .max = 3.0 }
	}
};

const pgsql_variable_validator pgsql_variable_validator_intervalstyle = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "postgres", "sql_standard", "postgres_verbose", "iso_8601", nullptr } 
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
	.validate = &pgsql_variable_validate_maintenance_work_mem_v3,
	.params = {
		.uint_range = {.min = 1024, .max = 2147483647 } // this range is in kB
	}
};
