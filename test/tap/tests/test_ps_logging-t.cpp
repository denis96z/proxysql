/**
 * @file test_ps_logging-t.cpp
 * @brief TAP test that verifies the logging of prepared statement parameters
 *		using an extended table definition.
 *
 * This test performs the following steps:
 *   1. Connects to ProxySQL via both a normal (proxy) and admin connection.
 *   2. Configures query logging first to BINARY and then to JSON.
 *   3. Creates a table with many field types:
 *		 - id INT PRIMARY KEY AUTO_INCREMENT
 *		 - col_date DATE
 *		 - col_time TIME
 *		 - col_timestamp TIMESTAMP
 *		 - col_datetime DATETIME
 *		 - col_int INT
 *		 - col_longint BIGINT
 *		 - col_blob BLOB
 *		 - col_decimal DECIMAL(10,2)
 *		 - col_year YEAR
 *		 - col_set SET('a','b','c','d')
 *		 - col_json JSON
 *   4. Inserts 20 rows using a prepared INSERT statement.
 *   5. Issues a series of prepared SELECT statements of the form:
 *		 SELECT * FROM test.prepared_log_test WHERE id=? AND colX = ?
 *	  For each non-key column (col_date, col_time, etc.) a different SELECT is executed.
 *   6. Verifies via stats_mysql_query_digest that the expected INSERT query digest is present.
 *
 * Note: The test assumes that logging format can be switched via:
 *	   SET PROXYSQL_MYSQL_LOGGER_FORMAT='BINARY' or 'JSON' and loaded with
 *	   LOAD MYSQL VARIABLES TO RUNTIME.
*/

#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "command_line.h"
#include "proxysql_utils.h" // Expects MYSQL_QUERY() macro defined here.
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

// Extended table creation query.
string create_table_query_ext() {
	return string(
		"CREATE TABLE test.prepared_log_test ("
		"id INT PRIMARY KEY AUTO_INCREMENT, "
		"col_date DATE, "
		"col_time TIME, "
		"col_timestamp TIMESTAMP, "
		"col_datetime DATETIME, "
		"col_int INT, "
		"col_longint BIGINT, "
		"col_blob BLOB, "
		"col_decimal DECIMAL(10,2), "
		"col_year YEAR, "
		"col_set SET('a','b','c','d'), "
		"col_json JSON"
		") ENGINE=InnoDB"
	);
}

// New function that returns the full table definition with extra data types.
string create_table_query_full() {
	return string(
		"CREATE TABLE test.prepared_log_test_full ("
		"id INT PRIMARY KEY AUTO_INCREMENT, "
		"col_date DATE, "
		"col_time TIME, "
		"col_timestamp TIMESTAMP, "
		"col_datetime DATETIME, "
		"col_int INT, "
		"col_tiny TINYINT, "			  // MYSQL_TYPE_TINY
		"col_float FLOAT, "			   // MYSQL_TYPE_FLOAT
		"col_int24 MEDIUMINT, "		   // MYSQL_TYPE_INT24
		"col_newdate DATE, "			  // MYSQL_TYPE_NEWDATE (using DATE)
		"col_varchar VARCHAR(50), "	   // MYSQL_TYPE_VARCHAR
		//"col_bit BIT(8), "				// MYSQL_TYPE_BIT
		"col_timestamp2 TIMESTAMP(6), "   // MYSQL_TYPE_TIMESTAMP2
		"col_datetime2 DATETIME(6), "	 // MYSQL_TYPE_DATETIME2
		"col_time2 TIME(6), "			 // MYSQL_TYPE_TIME2
		"col_json_extra JSON, "		   // MYSQL_TYPE_JSON
		"col_newdecimal DECIMAL(10,3), "	// MYSQL_TYPE_NEWDECIMAL
		"col_enum ENUM('x','y','z'), "	// MYSQL_TYPE_ENUM
		"col_set_extra SET('a','b','c'), " // MYSQL_TYPE_SET
		"col_tiny_blob TINYBLOB, "		 // MYSQL_TYPE_TINY_BLOB
		"col_medium_blob MEDIUMBLOB, "	 // MYSQL_TYPE_MEDIUM_BLOB
		"col_long_blob LONGBLOB "		 // MYSQL_TYPE_LONG_BLOB
		//"col_geometry GEOMETRY"		   // MYSQL_TYPE_GEOMETRY
		") ENGINE=InnoDB"
	);
}


// Extended INSERT query (inserts into all fields except id).
string insert_query_ext() {
	return string(
		"INSERT INTO test.prepared_log_test ("
		"col_date, col_time, col_timestamp, col_datetime, col_int, col_longint, col_blob, col_decimal, col_year, col_set, col_json"
		") VALUES (?,?,?,?,?,?,?,?,?,?,?)"
	);
}

// Generic SELECT query template: "SELECT * FROM test.prepared_log_test WHERE id=? AND %s=?"
// The second parameter column name is substituted.
string select_query_ext(const string& col_name) {
	return "SELECT * FROM test.prepared_log_test WHERE id=? AND " + col_name + "=?";
}

// Execute a prepared INSERT with extended fields.
bool do_prepared_insert_ext(MYSQL* conn,
							const string& col_date,
							const string& col_time,
							const string& col_timestamp,
							const string& col_datetime,
							int col_int,
							long long col_longint,
							const string& col_blob,
							double col_decimal,
							int col_year,
							const string& col_set,
							const string& col_json,
							int* inserted_id)
{
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt) {
		diag("mysql_stmt_init failed");
		return false;
	}
	string query = insert_query_ext();
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		diag("Extended INSERT prepare failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	MYSQL_BIND bind[11];
	memset(bind, 0, sizeof(bind));

	// Bind col_date (DATE) as string "YYYY-MM-DD".
	bind[0].buffer_type = MYSQL_TYPE_STRING;
	bind[0].buffer = (char*)col_date.c_str();
	unsigned long len_date = col_date.size();
	bind[0].buffer_length = len_date;
	bind[0].length = &len_date;

	// Bind col_time (TIME) as string "HH:MM:SS".
	bind[1].buffer_type = MYSQL_TYPE_STRING;
	bind[1].buffer = (char*)col_time.c_str();
	unsigned long len_time = col_time.size();
	bind[1].buffer_length = len_time;
	bind[1].length = &len_time;

	// Bind col_timestamp (TIMESTAMP) as string.
	bind[2].buffer_type = MYSQL_TYPE_STRING;
	bind[2].buffer = (char*)col_timestamp.c_str();
	unsigned long len_ts = col_timestamp.size();
	bind[2].buffer_length = len_ts;
	bind[2].length = &len_ts;

	// Bind col_datetime (DATETIME) as string.
	bind[3].buffer_type = MYSQL_TYPE_STRING;
	bind[3].buffer = (char*)col_datetime.c_str();
	unsigned long len_dt = col_datetime.size();
	bind[3].buffer_length = len_dt;
	bind[3].length = &len_dt;

	// Bind col_int as LONG.
	bind[4].buffer_type = MYSQL_TYPE_LONG;
	bind[4].buffer = (char*)&col_int;
	bind[4].is_null = 0;
	bind[4].length = 0;

	// Bind col_longint as LONGLONG.
	bind[5].buffer_type = MYSQL_TYPE_LONGLONG;
	bind[5].buffer = (char*)&col_longint;
	bind[5].is_null = 0;
	bind[5].length = 0;

	// Bind col_blob as BLOB.
	bind[6].buffer_type = MYSQL_TYPE_BLOB;
	bind[6].buffer = (char*)col_blob.c_str();
	unsigned long len_blob = col_blob.size();
	bind[6].buffer_length = len_blob;
	bind[6].length = &len_blob;

	// Bind col_decimal as DOUBLE.
	bind[7].buffer_type = MYSQL_TYPE_DOUBLE;
	bind[7].buffer = (char*)&col_decimal;
	bind[7].is_null = 0;
	bind[7].length = 0;

	// Bind col_year as SHORT.
	bind[8].buffer_type = MYSQL_TYPE_SHORT;
	bind[8].buffer = (char*)&col_year;
	bind[8].is_null = 0;
	bind[8].length = 0;

	// Bind col_set as STRING.
	bind[9].buffer_type = MYSQL_TYPE_STRING;
	bind[9].buffer = (char*)col_set.c_str();
	unsigned long len_set = col_set.size();
	bind[9].buffer_length = len_set;
	bind[9].length = &len_set;

	// Bind col_json as STRING.
	bind[10].buffer_type = MYSQL_TYPE_STRING;
	bind[10].buffer = (char*)col_json.c_str();
	unsigned long len_json = col_json.size();
	bind[10].buffer_length = len_json;
	bind[10].length = &len_json;

	if (mysql_stmt_bind_param(stmt, bind)) {
		diag("Extended INSERT bind failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("Extended INSERT execute failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	*inserted_id = (int)mysql_stmt_insert_id(stmt);
	mysql_stmt_close(stmt);
	return true;
}

// New function to execute a prepared INSERT for the full table.
bool do_prepared_insert_full(MYSQL* conn,
	const string& col_date,
	const string& col_time,
	const string& col_timestamp,
	const string& col_datetime,
	int col_int,
	int col_tiny,
	float col_float,
	int col_int24,
	const string& col_newdate,
	const string& col_varchar,
	const string& col_timestamp2,
	const string& col_datetime2,
	const string& col_time2,
	const string& col_json_extra,
	double col_newdecimal,
	const string& col_enum,
	const string& col_set_extra,
	const string& col_tiny_blob,
	const string& col_medium_blob,
	const string& col_long_blob,
	//const string& col_geometry, // e.g. WKT format: "POINT(1 2)"
	int* inserted_id)
	{
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt) {
		diag("mysql_stmt_init failed");
		return false;
	}
	string query = "INSERT INTO test.prepared_log_test_full ("
				   "col_date, col_time, col_timestamp, col_datetime, col_int, col_tiny, col_float, col_int24, "
				   "col_newdate, col_varchar, col_timestamp2, col_datetime2, col_time2, "
				   "col_json_extra, col_newdecimal, col_enum, col_set_extra, col_tiny_blob, col_medium_blob, col_long_blob"
				   ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		diag("Full INSERT prepare failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	MYSQL_BIND bind[20];
	memset(bind, 0, sizeof(bind));
	int idx = 0;
	// Bind col_date (DATE)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_date.c_str();
	unsigned long len0 = col_date.size(); bind[idx].buffer_length = len0; bind[idx].length = &len0; idx++;
	// Bind col_time (TIME)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_time.c_str();
	unsigned long len1 = col_time.size(); bind[idx].buffer_length = len1; bind[idx].length = &len1; idx++;
	// Bind col_timestamp (TIMESTAMP)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_timestamp.c_str();
	unsigned long len2 = col_timestamp.size(); bind[idx].buffer_length = len2; bind[idx].length = &len2; idx++;
	// Bind col_datetime (DATETIME)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_datetime.c_str();
	unsigned long len3 = col_datetime.size(); bind[idx].buffer_length = len3; bind[idx].length = &len3; idx++;
	// Bind col_int (INT)
	bind[idx].buffer_type = MYSQL_TYPE_LONG;
	bind[idx].buffer = (char*)&col_int;
	bind[idx].is_null = 0; bind[idx].length = 0; idx++;
	// Bind col_tiny (TINYINT)
	bind[idx].buffer_type = MYSQL_TYPE_TINY;
	bind[idx].buffer = (char*)&col_tiny;
	bind[idx].is_null = 0; bind[idx].length = 0; idx++;
	// Bind col_float (FLOAT)
	bind[idx].buffer_type = MYSQL_TYPE_FLOAT;
	bind[idx].buffer = (char*)&col_float;
	bind[idx].is_null = 0; bind[idx].length = 0; idx++;
	// Bind col_int24 (MEDIUMINT)
	bind[idx].buffer_type = MYSQL_TYPE_LONG;
	bind[idx].buffer = (char*)&col_int24;
	bind[idx].is_null = 0; bind[idx].length = 0; idx++;
	// Bind col_newdate (DATE) for NEWDATE
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_newdate.c_str();
	unsigned long len8 = col_newdate.size(); bind[idx].buffer_length = len8; bind[idx].length = &len8; idx++;
	// Bind col_varchar (VARCHAR)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_varchar.c_str();
	unsigned long len9 = col_varchar.size(); bind[idx].buffer_length = len9; bind[idx].length = &len9; idx++;
//	// Bind col_bit (BIT) as string.
//	bind[idx].buffer_type = MYSQL_TYPE_STRING;
//	bind[idx].buffer = (char*)col_bit.c_str();
//	unsigned long len10 = col_bit.size(); bind[idx].buffer_length = len10; bind[idx].length = &len10; idx++;
	// Bind col_timestamp2 (TIMESTAMP2) as string.
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_timestamp2.c_str();
	unsigned long len11 = col_timestamp2.size(); bind[idx].buffer_length = len11; bind[idx].length = &len11; idx++;
	// Bind col_datetime2 (DATETIME2) as string.
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_datetime2.c_str();
	unsigned long len12 = col_datetime2.size(); bind[idx].buffer_length = len12; bind[idx].length = &len12; idx++;
	// Bind col_time2 (TIME2) as string.
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_time2.c_str();
	unsigned long len13 = col_time2.size(); bind[idx].buffer_length = len13; bind[idx].length = &len13; idx++;
	// Bind col_json_extra (JSON)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_json_extra.c_str();
	unsigned long len14 = col_json_extra.size(); bind[idx].buffer_length = len14; bind[idx].length = &len14; idx++;
	// Bind col_newdecimal (NEWDECIMAL)
	bind[idx].buffer_type = MYSQL_TYPE_DOUBLE;
	bind[idx].buffer = (char*)&col_newdecimal;
	bind[idx].is_null = 0; bind[idx].length = 0; idx++;
	// Bind col_enum (ENUM)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_enum.c_str();
	unsigned long len16 = col_enum.size(); bind[idx].buffer_length = len16; bind[idx].length = &len16; idx++;
	// Bind col_set_extra (SET)
	bind[idx].buffer_type = MYSQL_TYPE_STRING;
	bind[idx].buffer = (char*)col_set_extra.c_str();
	unsigned long len17 = col_set_extra.size(); bind[idx].buffer_length = len17; bind[idx].length = &len17; idx++;
	// Bind col_tiny_blob (TINYBLOB)
	bind[idx].buffer_type = MYSQL_TYPE_BLOB;
	bind[idx].buffer = (char*)col_tiny_blob.c_str();
	unsigned long len18 = col_tiny_blob.size(); bind[idx].buffer_length = len18; bind[idx].length = &len18; idx++;
	// Bind col_medium_blob (MEDIUMBLOB)
	bind[idx].buffer_type = MYSQL_TYPE_BLOB;
	bind[idx].buffer = (char*)col_medium_blob.c_str();
	unsigned long len19 = col_medium_blob.size(); bind[idx].buffer_length = len19; bind[idx].length = &len19; idx++;
	// Bind col_long_blob (LONGBLOB)
	bind[idx].buffer_type = MYSQL_TYPE_BLOB;
	bind[idx].buffer = (char*)col_long_blob.c_str();
	unsigned long len20 = col_long_blob.size(); bind[idx].buffer_length = len20; bind[idx].length = &len20; idx++;
//	// Bind col_geometry (GEOMETRY) as string (WKT format)
//	bind[idx].buffer_type = MYSQL_TYPE_STRING;
//	bind[idx].buffer = (char*)col_geometry.c_str();
//	unsigned long len21 = col_geometry.size(); bind[idx].buffer_length = len21; bind[idx].length = &len21; idx++;

	if (mysql_stmt_bind_param(stmt, bind)) {
		diag("Full INSERT bind failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("Full INSERT execute failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	*inserted_id = (int)mysql_stmt_insert_id(stmt);
	mysql_stmt_close(stmt);
	return true;
}

// New function to perform a prepared SELECT from the full table.
// For simplicity, we select by id.
bool do_prepared_select_full(MYSQL* conn, int id, vector<string>& row_values) {
	string query = "SELECT "
				   "col_date, col_time, col_timestamp, col_datetime, col_int, col_tiny, col_float, col_int24, "
				   "col_newdate, col_varchar, col_timestamp2, col_datetime2, col_time2, "
				   "col_json_extra, col_newdecimal, col_enum, col_set_extra, col_tiny_blob, col_medium_blob, col_long_blob "
				   "FROM test.prepared_log_test_full WHERE id=?";
	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt) {
		diag("mysql_stmt_init failed");
		return false;
	}
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		diag("Full SELECT prepare failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	MYSQL_BIND param;
	memset(&param, 0, sizeof(param));
	param.buffer_type = MYSQL_TYPE_LONG;
	param.buffer = (char*)&id;
	param.is_null = 0;
	param.length = 0;
	if (mysql_stmt_bind_param(stmt, &param)) {
		diag("Full SELECT bind param failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("Full SELECT execute failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	// Bind 22 result columns.
	const int NUM_COLS = 22;
	char buffers[NUM_COLS][256] = {{0}};
	unsigned long lengths[NUM_COLS] = {0};
	MYSQL_BIND results[NUM_COLS];
	memset(results, 0, sizeof(results));
	for (int i = 0; i < NUM_COLS; i++) {
		results[i].buffer_type = MYSQL_TYPE_STRING;
		results[i].buffer = buffers[i];
		results[i].buffer_length = sizeof(buffers[i]);
		results[i].length = &lengths[i];
	}
	if (mysql_stmt_bind_result(stmt, results)) {
		diag("Full SELECT bind result failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_store_result(stmt)) {
		diag("Full SELECT store result failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	bool ret = false;
	if (!mysql_stmt_fetch(stmt)) {
		row_values.clear();
		for (int i = 0; i < NUM_COLS; i++) {
			row_values.push_back(string(buffers[i], lengths[i]));
		}
		ret = true;
	}
	mysql_stmt_close(stmt);
	return ret;
}



// Generic function to execute a prepared SELECT with two parameters.
// The query must have two placeholders. The first is an INT (id) and the second is a string.
bool do_prepared_select_generic(MYSQL* conn, string& query, int id, const string& param_value, vector<vector<string>>& rows) {
	// Special-case for col_json: use JSON_EXTRACT to compare the value.
	diag("do_prepared_select_generic: query=%s, id=%d, param_value=%s", query.c_str(), id, param_value.c_str());
	if (query.find("col_json") != string::npos) {
		query = "SELECT * FROM test.prepared_log_test WHERE id=? AND JSON_EXTRACT(col_json, '$.key') = ?";
	}

	MYSQL_STMT* stmt = mysql_stmt_init(conn);
	if (!stmt) {
		diag("mysql_stmt_init failed");
		return false;
	}
	if (mysql_stmt_prepare(stmt, query.c_str(), query.size())) {
		diag("Select prepare failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	// Bind two parameters.
	MYSQL_BIND params[2];
	memset(params, 0, sizeof(params));
	// First parameter: id (INT).
	params[0].buffer_type = MYSQL_TYPE_LONG;
	params[0].buffer = (char*)&id;
	params[0].is_null = 0;
	params[0].length = 0;
	// Second parameter: value (STRING).
	params[1].buffer_type = MYSQL_TYPE_STRING;
	params[1].buffer = (char*)param_value.c_str();
	unsigned long param_len = param_value.size();
	params[1].buffer_length = param_len;
	params[1].length = &param_len;

	if (mysql_stmt_bind_param(stmt, params)) {
		diag("Select bind param failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_execute(stmt)) {
		diag("Select execute failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	// Bind result columns (all 12 columns).
	int id_res = 0;
	char col_date[32] = {0};
	char col_time[32] = {0};
	char col_timestamp[32] = {0};
	char col_datetime[32] = {0};
	int col_int = 0;
	long long col_longint = 0;
	char col_blob[256] = {0};
	char col_decimal[32] = {0};
	int col_year = 0;
	char col_set[32] = {0};
	char col_json[256] = {0};
	unsigned long lengths[12] = {0};

	MYSQL_BIND results[12];
	memset(results, 0, sizeof(results));
	results[0].buffer_type = MYSQL_TYPE_LONG;
	results[0].buffer = (char*)&id_res;
	results[0].length = &lengths[0];

	results[1].buffer_type = MYSQL_TYPE_STRING;
	results[1].buffer = col_date;
	results[1].buffer_length = sizeof(col_date);
	results[1].length = &lengths[1];

	results[2].buffer_type = MYSQL_TYPE_STRING;
	results[2].buffer = col_time;
	results[2].buffer_length = sizeof(col_time);
	results[2].length = &lengths[2];

	results[3].buffer_type = MYSQL_TYPE_STRING;
	results[3].buffer = col_timestamp;
	results[3].buffer_length = sizeof(col_timestamp);
	results[3].length = &lengths[3];

	results[4].buffer_type = MYSQL_TYPE_STRING;
	results[4].buffer = col_datetime;
	results[4].buffer_length = sizeof(col_datetime);
	results[4].length = &lengths[4];

	results[5].buffer_type = MYSQL_TYPE_LONG;
	results[5].buffer = (char*)&col_int;
	results[5].length = &lengths[5];

	results[6].buffer_type = MYSQL_TYPE_LONGLONG;
	results[6].buffer = (char*)&col_longint;
	results[6].length = &lengths[6];

	results[7].buffer_type = MYSQL_TYPE_STRING;
	results[7].buffer = col_blob;
	results[7].buffer_length = sizeof(col_blob);
	results[7].length = &lengths[7];

	results[8].buffer_type = MYSQL_TYPE_STRING;
	results[8].buffer = col_decimal;
	results[8].buffer_length = sizeof(col_decimal);
	results[8].length = &lengths[8];

	results[9].buffer_type = MYSQL_TYPE_SHORT;
	results[9].buffer = (char*)&col_year;
	results[9].length = &lengths[9];

	results[10].buffer_type = MYSQL_TYPE_STRING;
	results[10].buffer = col_set;
	results[10].buffer_length = sizeof(col_set);
	results[10].length = &lengths[10];

	results[11].buffer_type = MYSQL_TYPE_STRING;
	results[11].buffer = col_json;
	results[11].buffer_length = sizeof(col_json);
	results[11].length = &lengths[11];

	if (mysql_stmt_bind_result(stmt, results)) {
		diag("Select bind result failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	if (mysql_stmt_store_result(stmt)) {
		diag("Select store result failed: %s", mysql_stmt_error(stmt));
		mysql_stmt_close(stmt);
		return false;
	}
	while (!mysql_stmt_fetch(stmt)) {
		vector<string> row;
		row.push_back(std::to_string(id_res));
		row.push_back(string(col_date, lengths[1]));
		row.push_back(string(col_time, lengths[2]));
		row.push_back(string(col_timestamp, lengths[3]));
		row.push_back(string(col_datetime, lengths[4]));
		row.push_back(std::to_string(col_int));
		row.push_back(std::to_string(col_longint));
		row.push_back(string(col_blob, lengths[7]));
		row.push_back(string(col_decimal, lengths[8]));
		row.push_back(std::to_string(col_year));
		row.push_back(string(col_set, lengths[10]));
		row.push_back(string(col_json, lengths[11]));
		rows.push_back(row);
	}
	mysql_stmt_close(stmt);
	return true;
}
  
int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to retrieve required environmental variables.");
		return EXIT_FAILURE;
	}

   // Run test in two logging formats: BINARY and JSON.
   // The test will create a table with many field types and perform prepared statements.
   // The test will verify that the expected INSERT query digest is present in stats_mysql_query_digest.
   // The test will also verify that the SELECT queries return the expected results.
   // The test will use the following logging modes:
   // - BINARY
   // - JSON
   // These modes are defined in the ProxySQL configuration.
   const vector<string> logging_modes = { "BINARY", "JSON" };
	// Insert 20 rows.
   const int NUM_ROWS = 20;
   vector<std::pair<string, string>> select_tests = {
	{ "col_date", "2025-04-01" },
	{ "col_time", "12:34:56" },
	{ "col_timestamp", "2025-04-03 12:34:56" },
	{ "col_datetime", "2025-04-03 12:34:56" },
	{ "col_int", std::to_string(10) },
	{ "col_longint", std::to_string(100) },
	{ "col_blob", "BlobData_1" },
	{ "col_decimal", "1.23" },
	{ "col_year", "2025" },
	{ "col_set", "c,d" },
	{ "col_json", "1" }
	};

	unsigned int p = 0;
	p = NUM_ROWS;
	p += select_tests.size() * 2; // check rows
	p += 1; // check digest
	p += 1; // INSERT on prepared_log_test_full
	p += 1; // SELECT on prepared_log_test_full
	p *= 2; // check logging modes
	plan(p);

   MYSQL* proxy = mysql_init(NULL);
   MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
							  NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "Admin connect failed: %s\n", mysql_error(admin));
		return EXIT_FAILURE;
   }
	if (!mysql_real_connect(proxy, cl.host, cl.username, cl.password,
							  NULL, cl.port, NULL, 0)) {
		fprintf(stderr, "Proxy connect failed: %s\n", mysql_error(proxy));
		return EXIT_FAILURE;
	}

	// Reset query digest statistics.
	MYSQL_QUERY(admin, "TRUNCATE stats_mysql_query_digest");

	{
		const char* log_query = "SELECT variable_value FROM global_variables WHERE variable_name LIKE 'mysql-eventslog_filename'";
		if (mysql_query(admin, log_query)) {
			diag("Failed to query logging file setting: %s", mysql_error(admin));
			exit(EXIT_FAILURE);
		}
		MYSQL_RES* res = mysql_store_result(admin);
		if (!res) {
			diag("Failed to store result for logging file setting: %s", mysql_error(admin));
			exit(EXIT_FAILURE);
		}
		int num_rows = mysql_num_rows(res);
		if (num_rows != 1) {
			diag("Expected exactly 1 row for logging file setting query, got %d", num_rows);
			mysql_free_result(res);
			exit(EXIT_FAILURE);
		}
		MYSQL_ROW row = mysql_fetch_row(res);
		if (!row || !row[0] || strlen(row[0]) == 0) {
			diag("Logging to file is not enabled: variable `mysql-eventslog_filename` is empty");
			mysql_free_result(res);
			exit(EXIT_FAILURE);
		}
		mysql_free_result(res);
	}
	// Run test in two logging formats: BINARY and JSON.
   
	for (auto mode : logging_modes) {
		diag("Configuring logging to %s format", mode.c_str());
		string set_log_mode;
		if (mode == "BINARY") {
			set_log_mode = "SET mysql-eventslog_format=1";
		} else if (mode == "JSON") {
			set_log_mode = "SET mysql-eventslog_format=2";
		}
		MYSQL_QUERY(admin, set_log_mode.c_str());
		MYSQL_QUERY(admin, "SET mysql-eventslog_default_log=1");
		MYSQL_QUERY(admin, "LOAD MYSQL VARIABLES TO RUNTIME");
		MYSQL_QUERY(proxy, "DROP TABLE IF EXISTS test.prepared_log_test");
		MYSQL_QUERY(proxy, create_table_query_ext().c_str());
		MYSQL_QUERY(proxy, "DROP TABLE IF EXISTS test.prepared_log_test_full");
		MYSQL_QUERY(proxy, create_table_query_full().c_str());

		
		for (int i = 1; i <= NUM_ROWS; i++) {
			// Use sample values. You may vary these as needed.
			string col_date = string("2025-04-") + (i < 10 ? "0" : "") + std::to_string(i);
			string col_time = "12:34:56";
			string col_timestamp = "2025-04-03 12:34:56";
			string col_datetime = "2025-04-03 12:34:56";
			int col_int = i * 10;
			long long col_longint = i * 100LL;
			string col_blob = "BlobData_" + std::to_string(i);
			double col_decimal = i * 1.23;
			int col_year = 2025;
			string col_set = (i % 2 == 0) ? "a,b" : "c,d";
			string col_json = "{\"key\": \"" + std::to_string(i) + "\"}";
			int inserted_id = 0;
			bool ins_ok = do_prepared_insert_ext(proxy, col_date, col_time, col_timestamp, col_datetime,
												  col_int, col_longint, col_blob, col_decimal,
												  col_year, col_set, col_json, &inserted_id);
			ok(ins_ok, "Extended prepared INSERT executed");
		}

		// For each non-key column, perform a prepared SELECT.
		// We use the first inserted row's id (assumed to be 1) and the value from that column.
		int sel_id = 1;
		vector<vector<string>> rows;
		// Define an array of pairs: {column name, sample value from row 1}
		
		for (auto& test : select_tests) {
			string sel_query = select_query_ext(test.first);
			rows.clear();
			bool sel_ok = do_prepared_select_generic(proxy, sel_query, sel_id, test.second, rows);
			ok(sel_ok, "%s", string("Select by " + test.first + " executed").c_str());
			ok(rows.size() == 1, "%s", string("Select by " + test.first + ( rows.size() == 1 ? "" : " DID NOT") + " returned exactly one row").c_str());
			diag("Select by %s returned %lu row(s) in logging mode %s . Query: \"%s\" . Parameter: %d , %s", 
				 test.first.c_str(), rows.size(), mode.c_str(), sel_query.c_str(), sel_id, test.second.c_str());
		}
		
		// Verify that stats_mysql_query_digest contains the expected INSERT digest.
		string exp_digest = "INSERT INTO test.prepared_log_test (col_date,col_time,col_timestamp,col_datetime,col_int,col_longint,col_blob,col_decimal,col_year,col_set,col_json) VALUES (?,?,?,...)";
		string digest_stats_query = "SELECT count_star from stats_mysql_query_digest WHERE digest_text=\"" + exp_digest + "\"";
		int rc = mysql_query(admin, digest_stats_query.c_str());
		if (rc == 0) {
			MYSQL_RES* myres = mysql_store_result(admin);
			MYSQL_ROW myrow = mysql_fetch_row(myres);
			if (myrow && myrow[0]) {
				int count_star = std::stoi(myrow[0]);
				diag("Digest count for INSERT: %d", count_star);
				ok(count_star > 0, "Query digest count is greater than zero");
			} else {
				diag("Digest not found for expected INSERT query");
				ok(false, "Query digest should be present");
			}
			mysql_free_result(myres);
		} else {
			diag("Failed to query stats_mysql_query_digest: %s", mysql_error(admin));
			ok(false, "Query stats_mysql_query_digest");
		}
		// Insert a single row with sample values.
		int inserted_id = 0;
		bool ins_ok = do_prepared_insert_full(proxy,
							  "2025-04-01",		 // col_date
							  "12:34:56",		   // col_time
							  "2025-04-03 12:34:56",  // col_timestamp
							  "2025-04-03 12:34:56",  // col_datetime
							  100,				  // col_int
							  10,				   // col_tiny
							  1.23f,				// col_float
							  123,				  // col_int24
							  "2025-04-01",		 // col_newdate
							  "TestString",		 // col_varchar
							  //"b'101010'",	   // col_bit (as string)
							  "2025-04-03 12:34:56.123456", // col_timestamp2
							  "2025-04-03 12:34:56.123456", // col_datetime2
							  "12:34:56.123456",	 // col_time2
							  "{\"key\":\"value\"}", // col_json_extra
							  4.567,				// col_newdecimal
							  "x",				  // col_enum
							  "a,b",				// col_set_extra
							  "TinyBlobData",	   // col_tiny_blob
							  "MediumBlobData",	 // col_medium_blob
							  "LongBlobData",	   // col_long_blob
							  //"POINT(1 2)",		 // col_geometry in WKT
							  &inserted_id);
		ok(ins_ok, "Full prepared INSERT executed");
		vector<string> full_row;
		bool sel_ok = do_prepared_select_full(proxy, inserted_id, full_row);
		ok(sel_ok, "Full prepared SELECT executed");
		diag("Full table row values:");
		for (size_t i = 0; i < full_row.size(); i++) {
			diag("Column %zu: '%s'", i, full_row[i].c_str());
		}
	}

	mysql_close(proxy);
	mysql_close(admin);


	return exit_status();
}
