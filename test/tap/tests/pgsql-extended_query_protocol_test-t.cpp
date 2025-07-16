// NOSONAR - TAP test files do not need to follow the same rules as production code
/**
 * @file pgsql-extended_query_protocol_test-t.cpp
 * @brief This TAP test suite verifies the correct handling of PostgreSQL's Extended Query Protocol 
 * through ProxySQL. It includes comprehensive tests for Parse, Bind, Execute, Describe, and Close message flows,
 * ensuring compliance with protocol semantics and robustness under edge cases.
 */

#include <fcntl.h>
#include <cerrno>
#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

int test_count = 1;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
using PGResultPtr = std::unique_ptr<PGresult, decltype(&PQclear)>;

enum ConnType {
	ADMIN,
	BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
	
	const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
	int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
	const char* username = (conn_type == BACKEND) ? cl.pgsql_root_username : cl.admin_username;
	const char* password = (conn_type == BACKEND) ? cl.pgsql_root_password : cl.admin_password;

	std::stringstream ss;

	ss << "host=" << host << " port=" << port;
	ss << " user=" << username << " password=" << password;
	ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

	if (options.empty() == false) {
		ss << " options='" << options << "'";
	}

	PGconn* conn = PQconnectdb(ss.str().c_str());
	if (PQstatus(conn) != CONNECTION_OK) {
		fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
		PQfinish(conn);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(conn, &PQfinish);
}

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
	auto fnResultType = [](const char* query) -> int {
		const char* fs = strchr(query, ' ');
		// NOSONAR: strlen is safe here as we control the input
		size_t qtlen = strlen(query); // NOSONAR
		if (fs != NULL) {
			qtlen = (fs - query) + 1;
		}
		char buf[qtlen];
		memcpy(buf, query, qtlen - 1);
		buf[qtlen - 1] = 0;

		if (strncasecmp(buf, "SELECT", sizeof("SELECT") - 1) == 0) {
			return PGRES_TUPLES_OK;
		}
		else if (strncasecmp(buf, "COPY", sizeof("COPY") - 1) == 0) {
			return PGRES_COPY_OUT;
		}

		return PGRES_COMMAND_OK;
		};


	for (const auto& query : queries) {
		diag("Running: %s", query.c_str());
		PGresult* res = PQexec(conn, query.c_str());
		bool success = PQresultStatus(res) == fnResultType(query.c_str());
		if (!success) {
			fprintf(stderr, "Failed to execute query '%s': %s\n",
				query.c_str(), PQerrorMessage(conn));
			PQclear(res);
			return false;
		}
		PQclear(res);
	}
	return true;
}

std::shared_ptr<PgConnection> create_connection() {
	auto conn = std::make_shared<PgConnection>(5000);
	try {
		conn->connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
	}
	catch (const PgException& e) {
		diag("Connection failed: %s", e.what());
		return nullptr;
	}
	return conn;
}

bool has_immediate_response(int sock) {
	if (sock < 0) return false;

	// Save current socket flags
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags == -1) return false;

	// Set non-blocking mode
	if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
		return false;
	}

	// Try to read one byte (without removing from buffer)
	char dummy;
	ssize_t n = recv(sock, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);

	// Restore original flags
	fcntl(sock, F_SETFL, flags);

	if (n > 0) {
		return true;  // Data available
	}
	else if (n == 0) {
		return true;  // Connection closed
	}
	else {
		// Check if error was due to no data
		return (errno != EAGAIN && errno != EWOULDBLOCK);
	}
}

/*bool no_immediate_response(int sock) {
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sock, &read_fds);

	timeval timeout{};
	timeout.tv_sec = 0;
	timeout.tv_usec = 100000; // 100ms timeout

	return select(sock + 1, &read_fds, nullptr, nullptr, &timeout) == 0;
}*/


void test_parse_without_sync() {
	diag("Test %d: Parse without sync should not respond", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Get raw socket for timeout check
		int sock = conn->getSocket();

		// Prepare without sync
		conn->prepareStatement("test_stmt", "SELECT 1", false);

		// Check for immediate response (should timeout)
		ok(!has_immediate_response(sock), "No response after parse without sync");

		// Now sync and verify completion
		conn->sendSync();

		char type;
		bool got_ready = 0;
		int parse_count = 0;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(parse_count == 1, "Received parse complete after sync (%d/1)", parse_count);
		ok(got_ready, "Received ready packet after sync");
		ok(other_count == 0, "No other messages received after sync (%d)", other_count);
	} 
	catch (const PgException& e) {
		ok(false, "Parse without sync test failed with errpr: %s", e.what());
	}
}

void test_parse_with_sync() {
	diag("Test %d: Parse with sync should respond immediately", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("test_stmt", "SELECT 1", true);
		ok(true, "Parse completes with sync enabled");
	}
	catch (const PgException& e) {
		ok(false, "Parse with sync test failed with error: %s", e.what());
	}
}

void test_malformed_packet() {
	diag("Test %d: Malformed parse packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage instead of parse message
		std::vector<uint8_t> garbage{ 0xDE, 0xAD, 0xBE, 0xEF };
		conn->sendMessage('P', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());
	
		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_empty_query() {
	diag("Test %d: Empty query string", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("empty_stmt", "", true);
		ok(true, "Empty query should succeed");
	}
	catch (const PgException& e) {
		ok(false, "Empty query string failed with error: %s", e.what());
	}
}

void test_multiple_parse() {
	diag("Test %d: Multiple parse without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send multiple parse commands
		conn->prepareStatement("stmt1", "SELECT 1", false);
		conn->prepareStatement("stmt2", "SELECT 2", false);
		conn->prepareStatement("stmt3", "SELECT 3", false);

		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		bool got_ready = false;
		int parse_count = 0;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(parse_count == 3, "Received all parse completes (%d/3)", parse_count);
		ok(got_ready, "Received ready packet after multiple parse");
		ok(other_count == 0, "No other messages received after multiple parse (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Multiple parse test faile with error: %s", e.what());
	}
}

void test_only_sync() {
	diag("Test %d: Sending only sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		bool got_ready = false;
		int other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(got_ready, "Received ready packet after sync");
		ok(other_count == 0, "No other messages received after sync (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Sending only sync test failed with error: %s", e.what());
	}
}

void test_empty_stmt() {
	diag("Test %d: Empty statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("", "SELECT 1", true);
		ok(true, "Empty statmement should succeed");
	} catch (const PgException& e) {
		ok(false, "Empty stmt failed with error: %s", e.what());
	}
}

void test_prepare_statment_mix() {
	diag("Test %d: Prepare statement + Query", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("test_stmt_mix", "SELECT 1", false);

		conn->sendQuery("SELECT 2");
		
		char type;
		int parse_count = 0;
		int row_desc_count = 0;
		int row_data_count = 0;
		int command_completion_count = 0;
		int other_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				row_desc_count++;
			} else if (type == PgConnection::DATA_ROW) {
				row_data_count++;
			} else if (type == PgConnection::COMMAND_COMPLETE) {
				command_completion_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(parse_count == 1, "Received parse complete for prepared statement (%d/1)", parse_count);
		ok(row_desc_count == 1, "Received row description for query (%d/1)", row_desc_count);
		ok(row_data_count == 1, "Received row data for query (%d/1)", row_data_count);
		ok(command_completion_count == 1, "Received command completion for query (%d/1)", command_completion_count);
		ok(got_ready, "Received ready for query");
		ok(other_count == 0, "No other messages received (%d)", other_count);
		
		// Now send sync
		conn->sendSync();

		// Should get ready for query
		got_ready = false;
		parse_count = 0;
		row_desc_count = 0;
		row_data_count = 0;
		command_completion_count = 0;
		other_count = 0;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				row_desc_count++;
			} else if (type == PgConnection::DATA_ROW) {
				row_data_count++;
			} else if (type == PgConnection::COMMAND_COMPLETE) {
				command_completion_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}
		// After sync, we should not receive any parse, row description, row data or command completion
		ok(parse_count == 0, "No parse complete after sync (%d/0)", parse_count);
		ok(row_desc_count == 0, "No row description after sync (%d/0)", row_desc_count);
		ok(row_data_count == 0, "No row data after sync (%d/0)", row_data_count);
		ok(command_completion_count == 0, "No command completion after sync (%d/0)", command_completion_count);
		ok(got_ready, "Received ready for query after sync");
		ok(other_count == 0, "No other messages received after sync (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, " Prepare statement + Query failed with error: %s", e.what());
	}
}

void test_invalid_query_parse_packet() {
	diag("Test %d: Invalid query in parse packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send multiple parse commands
		conn->prepareStatement("invalid_stmt_test", "SELECT * FROM dummy_table", false);

		// Send single sync
		conn->sendSync();

		// Should get 3 parse complete messages
		char type;
		int error_count = 0;
		bool got_ready = false;
		int other_count = 0;

		std::string errormsg;
		std::string errorcode;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::ERROR_RESPONSE) {
				error_count++;

				BufferReader reader(buffer);
				char field;
				while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
					if (field == 'M') {
						errormsg = reader.readString();
					} else if (field == 'C') {
						errorcode = reader.readString();
					} else {
						reader.readString(); // Skip other fields
					}
				}
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(error_count == 1, "Received error response (%d)", error_count);
		ok(errorcode == "42P01", "Received undefined table error code: %s", errorcode.c_str());
		 ok(errormsg.find("relation \"dummy_table\" does not exist") != std::string::npos, 
			   "Received expected error message: %s", errormsg.c_str());
		
		ok(got_ready, "Got ready for query packet");
		ok(other_count == 0, "No other messages received (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Invalid query in parse packet failed with error: %s", e.what());
	}
}

bool test_text_binary_mix() {
	PGconn* conn = PQconnectdb("host=localhost dbname=postgres user=postgres password=postgres sslmode='disable'");

	ok(PQstatus(conn) == CONNECTION_OK, "Connected to database");

	PGresult* res;

	// Setup: ensure table exists
	res = PQexec(conn, "CREATE TEMP TABLE test_bin_text(id integer)");
	PQclear(res);
	res = PQexec(conn, "INSERT INTO test_bin_text VALUES (42)");
	PQclear(res);

	// 1. Prepare statement with declared parameter type as 'text'
	res = PQprepare(conn, "stmt1", "SELECT * FROM test_bin_text WHERE id = $1", 1, nullptr); // 25 = TEXTOID
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Prepare failed: %s", PQerrorMessage(conn));
	}
	ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Prepared statement with param type text");
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);
	// 2. Attempt to bind binary-formatted int32 to text param
	int32_t intval = htonl(42); // Network byte order
	const char* paramValues[1] = { (char*)&intval };
	int paramLengths[1] = { sizeof(intval) };
	int paramFormats[1] = { 1 }; // Binary format
	Oid resultFormat = 0;


	res = PQexecPrepared(conn, "stmt1", 1, paramValues, paramLengths, paramFormats, resultFormat);

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		diag("Unexpectedly succeeded: binary int bound to text param");
	}
	else {
		diag("Expected failure: %s", PQerrorMessage(conn));
	}

	ok(PQresultStatus(res) != PGRES_TUPLES_OK, "Binary format to text param fails as expected");

	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	const char* paramValues1[1] = { "42" };
	res = PQexecPrepared(conn, "stmt1", 1, paramValues1, 0, NULL, NULL);
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	PQfinish(conn);
	return 0;
}

bool test_text_binary_mix2() {
	PGconn* conn = PQconnectdb("host=localhost dbname=postgres user=postgres password=postgres sslmode='disable'");

	ok(PQstatus(conn) == CONNECTION_OK, "Connected to database");

	PGresult* res;

	// 1. Prepare statement with declared parameter type as 'text'
	res = PQprepare(conn, "stmt1", "SELECT $1", 1, nullptr); // 25 = TEXTOID
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		diag("Prepare failed: %s", PQerrorMessage(conn));
	}
	ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Prepared statement with param type text");
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);
	// 2. Attempt to bind binary-formatted int32 to text param
	int32_t intval = htonl(42); // Network byte order
	const char* paramValues[1] = { (char*)&intval };
	int paramLengths[1] = { sizeof(intval) };
	int paramFormats[1] = { 1 }; // Binary format
	Oid resultFormat = 0;


	res = PQexecPrepared(conn, "stmt1", 1, paramValues, paramLengths, paramFormats, resultFormat);

	if (PQresultStatus(res) == PGRES_TUPLES_OK) {
		diag("Unexpectedly succeeded: binary int bound to text param");
	}
	else {
		diag("Expected failure: %s", PQerrorMessage(conn));
	}

	ok(PQresultStatus(res) != PGRES_TUPLES_OK, "Binary format to text param fails as expected");

	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	const char* paramValues1[1] = { "42" };
	res = PQexecPrepared(conn, "stmt1", 1, paramValues1, 0, NULL, NULL);
	PQclear(res);

	res = PQdescribePrepared(conn, "stmt1");
	PQclear(res);

	PQfinish(conn);
	return 0;
}

void test_describe_existing_statement() {
	diag("Test %d: Describe existing prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("valid_stmt", "SELECT 1", true);

		// Describe the prepared statement
		conn->describeStatement("valid_stmt", true);

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION,
				"Received parameter description");

			// Read parameter description
			BufferReader reader(buffer);
			int paramCount = reader.readInt16();
			ok(paramCount == 0, "No parameters in prepared statement (%d/0)", paramCount);
		}

		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ROW_DESCRIPTION,
				"Received row description");

			BufferReader reader(buffer);
			// Read row description
			int fieldCount = reader.readInt16();
			ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
			// Read field name
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");

			// Read field table OID
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");

			// Read field attribute number
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

			// Read field type OID
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");

			// Read field type size
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");

			// Read field type modifier
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");

			// Read field format code
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe");
	}
	catch (const PgException& e) {
		ok(false, "Describe existing prepared statement failed with error: %s", e.what());
	}
}

void test_describe_nonexistent_statement() {
	diag("Test %d: Describe non-existent prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Describe unknown statement
		conn->describeStatement("ghost_stmt", true);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for non-existent statement");
		
		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);

		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe non-existent prepared statement failed with error: %s", e.what());
	}
}

void test_describe_without_sync() {
	diag("Test %d: Describe without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_stmt", "SELECT 1", false);
		conn->describeStatement("async_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No immediate response after describe without sync");

		conn->sendSync();
	  
		char type;
		std::vector<uint8_t> buffer;
		int parse_count = 0;
		int param_desc_count = 0;
		int row_desc_count = 0;
		bool gotReady = false;

		while (!gotReady) {
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARSE_COMPLETE) {
				parse_count++;
			} else if (type == PgConnection::PARAMETER_DESCRIPTION) {
				param_desc_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				row_desc_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				gotReady = true;
			} else if (type == PgConnection::ERROR_RESPONSE) {
				BufferReader reader(buffer);
				std::string errorMsg;
				char field;
				while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
					if (field == 'M') errorMsg = reader.readString();
					else reader.readString();
				}
				throw PgException("Error: " + errorMsg);
			}
		}

		ok(parse_count == 1, "Received ParseComplete (%d/1)", parse_count);
		ok(param_desc_count == 1, "Received ParameterDescription (%d/1)", param_desc_count);
		ok(row_desc_count == 1, "Received RowDescription (%d/1)", row_desc_count);
		ok(gotReady, "Sync completed after describe");
	}
	catch (const PgException& e) {
		ok(false, "Describe without sync failed with error:%s", e.what());
	}
}

void test_describe_malformed_packet() {
	diag("Test %d: Malformed describe packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage describe message
		std::vector<uint8_t> garbage{ 'X' };
		conn->sendMessage('D', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_describe_after_close_statement() {
	diag("Test %d: Describe after statement close", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("temp_stmt", "SELECT 1", true);
		conn->closeStatement("temp_stmt", true);
		conn->describeStatement("temp_stmt", true);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE, "Received error for closed statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after closed statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe after statement close failed with error: %s", e.what());
	}
}

void test_multiple_describe_calls() {
	diag("Test %d: Multiple describe calls", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("multi_desc", "SELECT 1", true);

		// First describe
		conn->describeStatement("multi_desc", false);
		// Second describe
		conn->describeStatement("multi_desc", false);
		conn->sendSync();

		int param_desc_count = 0;
		int desc_count = 0;
		int other_count = 0;
		char type;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);

			if (type == PgConnection::PARAMETER_DESCRIPTION) {
				param_desc_count++;
			} else if (type == PgConnection::ROW_DESCRIPTION) {
				desc_count++;
			} else if (type == PgConnection::READY_FOR_QUERY) {
				got_ready = true;
			} else {
				other_count++;
			}
		}

		ok(param_desc_count == 2, "Received parameter description (%d/2)", param_desc_count);
		ok(desc_count == 2, "Received description packets (%d/2)", desc_count);
		ok(got_ready, "Received ready for query after multiple describes");
		ok(other_count == 0, "No other messages received after multiple describes (%d)", other_count);
	}
	catch (const PgException& e) {
		ok(false, "Multiple describe calls failed with error: %s", e.what());
	}
}

void test_describe_parameter_types() {
	diag("Test %d: Verify parameter type reporting", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare statement with multiple parameter types
		conn->prepareStatement("param_types",
			"SELECT $1::int, $2::text, $3::bool",
			true);

		// Describe prepared statement
		conn->describeStatement("param_types", true);

		// Verify parameter description
		char type;
		std::vector<uint8_t> param_buffer;
		conn->readMessage(type, param_buffer);

		ok(type == PgConnection::PARAMETER_DESCRIPTION,
			"Received parameter description");

		// Parse parameter OIDs (format: [count] + [oids])
		if (param_buffer.size() >= 2) {
			int16_t num_params = (param_buffer[0] << 8) | param_buffer[1];
			ok(num_params == 3, "Three parameters reported");

			// Verify OIDs (int=23, text=25, bool=16)
			if (num_params == 3 && param_buffer.size() >= 8) {
				uint32_t oid1 = (param_buffer[2] << 24) | (param_buffer[3] << 16)
					| (param_buffer[4] << 8) | param_buffer[5];
				uint32_t oid2 = (param_buffer[6] << 24) | (param_buffer[7] << 16)
					| (param_buffer[8] << 8) | param_buffer[9];
				uint32_t oid3 = (param_buffer[10] << 24) | (param_buffer[11] << 16)
					| (param_buffer[12] << 8) | param_buffer[13];

				ok(oid1 == 23, "Parameter 1 type is int (OID: %u)", oid1);
				ok(oid2 == 25, "Parameter 2 type is text (OID: %u)", oid2);
				ok(oid3 == 16, "Parameter 3 type is bool (OID: %u)", oid3);
			} else {
				ok(false, "Invalid parameter description size");
			}
		} else {
			ok(false, "Invalid parameter description size");
		}

		// Read row description (should be empty for this query)
		std::vector<uint8_t> row_buffer;
		conn->readMessage(type, row_buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description after parameter description");
		// Verify no fields in row description
		BufferReader reader(row_buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 3, "No fields in row description (%d/3)", num_fields);

		// First field metadata
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "int4", "Field name is 'int4'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 23, "Field type OID is 23 (integer)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == 4, "Field type size is 4 (integer size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
   
		// Second field metadata
		fieldName = reader.readString();
		ok(fieldName == "text", "Field name is 'text'");
		tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");
		attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
		typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");
		typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (variable length)");
		typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");
		formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
		// Third field metadata
		fieldName = reader.readString();
			
		ok(fieldName == "bool", "Field name is 'bool'");
		tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");
		attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
		typeOid = reader.readInt32();
		ok(typeOid == 16, "Field type OID is 16 (boolean)");
		typeSize = reader.readInt16();
		ok(typeSize == 1, "Field type size is 1 (boolean size)");
		typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");
		formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");

		// Read ready for query
		conn->readMessage(type, row_buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after parameter description");
	}
	catch (const PgException& e) {
		ok(false, "Parameter type verification failed with error:%s", e.what());
	}
}

void test_describe_result_metadata() {
	diag("Test %d: Verify result metadata accuracy", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare complex query
		conn->prepareStatement("result_meta",
			"SELECT 1::int AS id, 'test'::text AS name, true::bool AS flag",
			true);

		// Describe prepared statement
		conn->describeStatement("result_meta", true);

		char type;
		std::vector<uint8_t> buffer;
		// Read parameter description
		{
			conn->readMessage(type, buffer);
			ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received parameter description");
			BufferReader reader(buffer);
			int16_t param_count = reader.readInt16();
			for (int i = 0; i < param_count; i++) {
				reader.readInt32();  // Skip parameter type OID
			}
		}
		// Read row description
		int16_t num_fields = 0;
		std::vector<std::tuple<std::string, uint32_t>> fields;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received row description");
		BufferReader reader(buffer);
		num_fields = reader.readInt16();

		ok(num_fields == 3, "Three result columns");

		for (int i = 0; i < num_fields; i++) {
			std::string name = reader.readString();
			reader.readInt32();   // Skip table OID
			reader.readInt16();   // Skip column attr num
			uint32_t type_oid = reader.readInt32();
			reader.readInt16();   // Skip type size
			reader.readInt32();   // Skip type modifier
			reader.readInt16();   // Skip format

			fields.emplace_back(name, type_oid);
		}

		// Verify metadata
		ok(fields.size() == 3, "Result has 3 fields (%zu/3)", fields.size());
		ok(std::get<0>(fields[0]) == "id" && std::get<1>(fields[0]) == 23,
			"Field 1: id (OID: %u)", std::get<1>(fields[0]));
		ok(std::get<0>(fields[1]) == "name" && std::get<1>(fields[1]) == 25,
			"Field 2: name (OID: %u)", std::get<1>(fields[1]));
		ok(std::get<0>(fields[2]) == "flag" && std::get<1>(fields[2]) == 16,
			"Field 3: flag (OID: %u)", std::get<1>(fields[2]));

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after result metadata");
	}
	catch (const PgException& e) {
		ok(false, "Result metadata verification failed with error:%s", e.what());
	}
}

void test_describe_after_execute() {
	diag("Test %d: Describe after execution", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
	   // conn->prepareStatement("post_exec", , true);

		// Execute statement
	   // const char* param = "5";
	  //  conn->sendExecute("post_exec", 1, &param, nullptr, nullptr, true);
		PgConnection::Param param = { "5", 1 };
		conn->executeParams("post_exec", "SELECT $1::int", { param });
		conn->readResult();

		// Describe after execution
		conn->describeStatement("post_exec", true);

		// Verify response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer); // Param desc
		ok(type == PgConnection::PARAMETER_DESCRIPTION,
			"Received parameter description after execution");
		conn->readMessage(type, buffer); // Row desc
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description after execution");
		conn->readMessage(type, buffer); // Ready for query
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after execution");

		ok(true, "Describe works after execution");
	}
	catch (const PgException& e) {
		diag("Exception: %s", e.what());
		ok(false, "Describe after execute failed");
	}
}

void test_describe_prepared_noname() {
	diag("Test %d: Describe prepared with noname statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;
	try {
		// Prepare a statement without a name
		conn->prepareStatement("", "SELECT 1", true);
		// Describe the prepared statement
		conn->describeStatement("", true);
		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARAMETER_DESCRIPTION,
			"Received parameter description for unnamed statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description for unnamed statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe unnamed statement");
	}
	catch (const PgException& e) {
		ok(false, "Describe prepared with noname failed with error:%s", e.what());
	}
}


void test_close_existing_statement() {
	diag("Test %d: Close existing prepared statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a valid statement
		conn->prepareStatement("existing_stmt", "SELECT 1", true);

		// Close the statement
		conn->closeStatement("existing_stmt", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for existing statement");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after close existing statement");

		// Verify statement is actually closed
		conn->describeStatement("existing_stmt", true);
		conn->readMessage(type, buffer);  // Should get error
		ok(type == PgConnection::ERROR_RESPONSE,
				"Describe fails after close");
		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query");
	}
	catch (const PgException& e) {
		ok(false, "Close existing statement failed with error:%s", e.what());
	}
}

void test_close_nonexistent_statement() {
	diag("Test %d: Close non-existent statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Close unknown statement
		conn->closeStatement("ghost_stmt", false);
		conn->sendSync();

		// Should still get CloseComplete
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Close non-existent failed with error:%s", e.what());
	}
}

void test_close_unnamed_statement() {
	diag("Test %d: Close unnamed statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare unnamed statement
		conn->prepareStatement("", "SELECT 1", false);
		conn->sendSync();
		conn->waitForMessage(PgConnection::PARSE_COMPLETE, "parse complete", true);

		// Close unnamed statement
		conn->closeStatement("", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete for unnamed statement");
		
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after close unnamed statement");
		
		// Verify closed
		conn->describeStatement("", true);
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Describe fails for closed unnamed statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());
	}
	catch (const PgException& e) {
		ok(false, "Close unnamed failed with error:%s", e.what());
	}
}

void test_close_after_execute() {
	diag("Test %d: Close after successful execution", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare and execute
		conn->prepareStatement("post_exec_stmt", "SELECT $1::int", true);
		PgConnection::Param param = { "1", 1 };
		conn->executeParams("post_exec_stmt", "SELECT $1::int", { param });
		conn->readResult();

		// Close after execution
		conn->closeStatement("post_exec_stmt", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received CloseComplete after execution");

		// Verify closed
		try {
			conn->executeParams("post_exec_stmt", "SELECT $1::int", { param });
			conn->readResult();
			ok(false, "Execute succeeded after close");
		}
		catch (...) {
			ok(true, "Execute fails after close");
		}
	}
	catch (const PgException& e) {
		ok(false, "Close after execute failed with error:%s", e.what());
	}
}

void test_close_without_sync() {
	diag("Test %d: Close without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_close_stmt", "SELECT 1", false);

		// Close without sync
		conn->closeStatement("async_close_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No immediate response after close without sync");

		// Send sync and verify responses
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		bool gotParseComplete = false;
		bool gotCloseComplete = false;
		bool gotReady = false;

		while (!gotReady) {
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) gotParseComplete = true;
			else if (type == PgConnection::CLOSE_COMPLETE) gotCloseComplete = true;
			else if (type == PgConnection::READY_FOR_QUERY) gotReady = true;
		}

		ok(gotParseComplete, "Received ParseComplete");
		ok(gotCloseComplete, "Received CloseComplete");
		ok(gotReady, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close without sync failed with error:%s", e.what());
	}
}

void test_multiple_close_without_sync() {
	diag("Test %d: Multiple close without sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare multiple statements
		conn->prepareStatement("multi_close_1", "SELECT 1", false);
		conn->prepareStatement("multi_close_2", "SELECT 2", false);
		conn->prepareStatement("multi_close_3", "SELECT 3", false);

		// Close without sync
		conn->closeStatement("multi_close_1", false);
		conn->closeStatement("multi_close_2", false);
		conn->closeStatement("multi_close_3", false);

		// Send sync
		conn->sendSync();

		// Verify responses
		char type;
		int close_count = 0;
		int parse_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::CLOSE_COMPLETE) close_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 3, "Received 3 parse completes");
		ok(close_count == 3, "Received 3 close completes");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Multiple close failed with error:%s", e.what());
	}
}

void test_close_malformed_packet() {
	diag("Test %d: Malformed close packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage close message (invalid target type)
		std::vector<uint8_t> garbage;
		garbage.push_back('X');  // Invalid target type
		garbage.push_back(0);	// Null-terminated empty name
		conn->sendMessage('C', garbage);


		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_close_twice() {
	diag("Test %d: Close statement twice", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("dupe_close", "SELECT 1", true);

		// First close
		conn->closeStatement("dupe_close", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE, "First close success");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "First close returns ReadyForQuery");

		// Second close
		conn->closeStatement("dupe_close", false);
		conn->sendSync();
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Second close returns CloseComplete");
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Second close returns ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close twice failed with error:%s", e.what());
	}
}

/*
void test_close_during_transaction() {
	diag("Test %d: Close during transaction", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Start transaction
		conn->sendQuery("BEGIN");
		conn->consumeInputUntilReady();

		// Prepare and close in transaction
		conn->prepareStatement("tx_stmt", "SELECT 1", true);
		conn->closeStatement("tx_stmt", true);

		// Rollback transaction
		conn->sendQuery("ROLLBACK");
		conn->consumeInputUntilReady();

		// Verify statement remains closed
		try {
			char type;
			std::vector<uint8_t> buffer;
			conn->describeStatement("tx_stmt", true);
			conn->readMessage(type, buffer);
			ok(type == PgConnection::ERROR_RESPONSE,
				"Describe fails after transaction rollback");
		}
		catch (...) {
			ok(true, "Statement remains closed after rollback");
		}
	}
	catch (const PgException& e) {
		ok(false, "Close during transaction failed with error:%s", e.what());
	}
}*/

void test_close_without_prepare() {
	diag("Test %d: Close without preparing", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Close without preparing first
		conn->closeStatement("never_prepared", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Close succeeds for non-prepared statement");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after close without prepare");
	}
	catch (const PgException& e) {
		ok(false, "Close without prepare failed with error:%s", e.what());
	}
}

void test_close_during_pending_ops() {
	diag("Test %d: Close during pending operations", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();

		// Start parse without sync
		conn->prepareStatement("pending_stmt", "SELECT 1", false);

		// Close without sync
		conn->closeStatement("pending_stmt", false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock),
			"No response during pending operations");

		// Send sync and verify responses
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete after close during pending ops");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE, "Received CloseComplete after close during pending ops");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after close during pending ops");
	}
	catch (const PgException& e) {
		ok(false, "Close during pending ops failed with error:%s", e.what());
	}
}

void test_close_all_types() {
	diag("Test %d: Close all types of targets", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare statements
		conn->prepareStatement("named_stmt", "SELECT 1", false);
		conn->prepareStatement("", "SELECT 2", false);  // Unnamed

		// Close named statement
		conn->closeStatement("named_stmt", false);

		// Close unnamed statement
		conn->closeStatement("", false);

		// Close non-existent (should still work)
		conn->closeStatement("ghost", false);

		// Send sync
		conn->sendSync();

		// Verify responses
		char type;
		int close_count = 0;
		int parse_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::CLOSE_COMPLETE) close_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 2, "Received 2 parse completes");
		ok(close_count == 3, "Received 3 close completes");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Close all types failed with error:%s", e.what());
	}
}

void test_parse_execute_without_bind() {
	diag("Test %d: Unnamed Prepared and Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a statement
		conn->prepareStatement("", "SELECT 1", true);
		// Execute statement directly
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000", "Received ERRCODE_UNDEFINED_CURSOR Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Unnamed Prepared and Execute failed with error:%s", e.what());
	}
}

void test_bind_basic() {
	diag("Test %d: Basic Bind and Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Prepare a statement
		conn->prepareStatement("basic_bind", "SELECT $1::int AS num", false);

		conn->describeStatement("basic_bind", false);
		// Bind parameters directly to statement
		PgConnection::Param param = { "42", 0 };
		conn->bindStatement("basic_bind", "", { param }, {}, false);
		
		// Execute statement directly
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify results
		char type;
		std::vector<uint8_t> buffer;

		// Read parse complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARSE_COMPLETE, "Received ParseComplete");

		// Read parameter description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::PARAMETER_DESCRIPTION, "Received ParameterDescription");
		BufferReader reader(buffer);
		int16_t num_params = reader.readInt16();
		ok(num_params == 1, "One parameter reported");
		if (num_params == 1 && buffer.size() >= 4) {
			uint32_t oid = (buffer[2] << 24) | (buffer[3] << 16)
				| (buffer[4] << 8) | buffer[5];
			ok(oid == 23, "Parameter type is int (OID: %u)", oid);
		} else {
			ok(false, "Invalid parameter description size");
		}
		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		// Verify row description
		reader = BufferReader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "num", "Field name is 'num'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Verify row description
		conn->readMessage(type, buffer);
		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "num", "Field name is 'num'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		// Read data row
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		// Verify data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 8) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 2, "Column length is 2");
			// Read column data
			buffer = reader.readBytes(column_length);
			ok(buffer[0] == '4' && buffer[1] == '2', "Column value is 42 (expected)");
		}
		else {
			ok(false, "Invalid data row size");
		}
		// Read command complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Basic Bind/Execute failed with error:%s", e.what());
	}
}

void test_bind_without_sync() {
	diag("Test %d: Bind without Sync", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		int sock = conn->getSocket();
		conn->prepareStatement("async_bind", "SELECT $1::int", false);

		// Bind without sync
		PgConnection::Param param = { "5", 0 };
		conn->bindStatement("async_bind", "", { param }, {}, false);

		// Shouldn't get immediate response
		ok(!has_immediate_response(sock), "No immediate response after bind without sync");

		// Execute without sync
		conn->executeStatement(0, false);

		// Send sync and verify responses
		conn->sendSync();

		char type;
		int parse_count = 0;
		int bind_count = 0;
		int execute_count = 0;
		bool got_ready = false;

		while (!got_ready) {
			std::vector<uint8_t> buffer;
			conn->readMessage(type, buffer);
			if (type == PgConnection::PARSE_COMPLETE) parse_count++;
			else if (type == PgConnection::BIND_COMPLETE) bind_count++;
			else if (type == PgConnection::DATA_ROW) execute_count++;
			else if (type == PgConnection::READY_FOR_QUERY) got_ready = true;
		}

		ok(parse_count == 1, "Received ParseComplete");
		ok(bind_count == 1, "Received BindComplete");
		ok(execute_count == 1, "Received DataRow");
		ok(got_ready, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Bind without sync failed with error:%s", e.what());
	}
}

void test_bind_nonexistent_statement() {
	diag("Test %d: Bind to non-existent statement", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		PgConnection::Param param = { "test", 1 };
		conn->bindStatement("ghost_stmt", "", { param }, {}, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for non-existent statement");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "26000", "Received ERRCODE_INVALID_SQL_STATEMENT_NAME Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after bind to non-existent statement");
	}
	catch (const PgException& e) {
		ok(false, "Bind to non-existent statement failed with error:%s", e.what());
	}
}

void test_bind_incorrect_parameters() {
	diag("Test %d: Bind with incorrect parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("incorrect_params", "SELECT $1::int, $2::text", true);

		// Pass only one parameter instead of two
		PgConnection::Param param = { "42", 1 };
		conn->bindStatement("incorrect_params", "", { param }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete for incorrect parameters");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received ErrorResponse for incorrect parameters");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery after bind with incorrect parameters");
	}
	catch (const PgException& e) {
		ok(false, "Bind failed with incorrect parameters: %s", e.what());
	}
}

void test_binary_parameters() {
	diag("Test %d: Bind binary parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("binary_params", "SELECT $1::int", true);

		// Create binary representation of integer 42 (network byte order)
		int32_t bin_value = htonl(42);
		PgConnection::Param param = {
			std::string(reinterpret_cast<char*>(&bin_value), sizeof(bin_value)),
			1 // Binary format
		};

		conn->bindStatement("binary_params", "", { param }, { 1 }, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		// Verify we got a binary result
		char type;
		std::vector<uint8_t> buffer;
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		// Verify row description
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "int4", "Field name is 'int4'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 1, "Field format code is 1 (binary format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		// Read data row
		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");
		// Verify data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 8) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 4, "Column length is 4 (int32 size)");
			// Read column data
			int32_t val = reader.readInt32();
			ok(val == 42, "Column value is 42 (expected)");
		}

		// Read command complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Binary parameters test failed with error:%s", e.what());
	}
}

void test_bind_large_data() {
	diag("Test %d: Bind with large data", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("large_data", "SELECT length($1::text)", true);

		// Create 1MB string
		std::string large_data(1024 * 1024, 'X');
		PgConnection::Param param = { large_data, 1 };

		conn->bindStatement("large_data", "", { param }, {1}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");

		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "length", "Field name is 'length'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 23, "Field type OID is 23 (integer)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 4, "Field type size is 4 (integer size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 1, "Field format code is 1 (binary format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		if (num_fields == 1) {
			int32_t len = reader.readInt32();
			if (len == 4) {  // Length of int32
				int32_t val = reader.readInt32();
				ok(val == 1024 * 1024, "Received correct length: %d", val);
			}
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "Large data test failed with error:%s", e.what());
	}
}

void test_bind_null_parameters() {
	diag("Test %d: Bind with NULL parameters", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("null_params", "SELECT $1::int IS NULL", true);

		// Bind NULL parameter
		std::vector<PgConnection::Param> params = { { {}, 1} };  // is_null = true
		conn->bindStatement("null_params", "", params, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::BIND_COMPLETE, "Received BindComplete");

		// Read row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION, "Received RowDescription");
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in row description (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 20) {
			// Read field metadata
			std::string fieldName = reader.readString();
			ok(fieldName == "?column?", "Field name is '?column?'");
			unsigned int tableOid = reader.readInt32();
			ok(tableOid == 0, "Field table OID is 0 (no table)");
			unsigned int attrNum = reader.readInt16();
			ok(attrNum == 0, "Field attribute number is 0 (no specific column)");
			unsigned int typeOid = reader.readInt32();
			ok(typeOid == 16, "Field type OID is 16 (boolean)");
			unsigned int typeSize = reader.readInt16();
			ok(typeSize == 1, "Field type size is 1 (boolean size)");
			unsigned int typeModifier = reader.readInt32();
			ok(typeModifier == -1, "Field type modifier is -1 (default)");
			unsigned int formatCode = reader.readInt16();
			ok(formatCode == 0, "Field format code is 0 (text format)");
		}
		else {
			ok(false, "Invalid row description size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received DataRow");

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		if (num_fields == 1) {
			int32_t len = reader.readInt32();
			if (len == 1) {
				char val = reader.readByte();
				ok(val == 't', "Received correct NULL check: %c", val);
			}
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY, "Received ReadyForQuery");
	}
	catch (const PgException& e) {
		ok(false, "NULL parameter test failed with error:%s", e.what());
	}
}

void test_malformed_bind_packet() {
	diag("Test %d: Malformed Bind packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage bind message
		std::vector<uint8_t> garbage{ 'X'};
		conn->sendMessage('B', garbage);

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

void test_malformed_execute_packet() {
	diag("Test %d: Malformed Execute packet", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		// Send garbage execute message
		std::vector<uint8_t> garbage{ 'X' };
		conn->sendMessage('E', garbage);

		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "08P01", "Received ERRCODE_PROTOCOL_VIOLATION Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(false, "Session should be terminated by server");
	}
	catch (const PgException& e) {
		ok(true, "Session should be terminated error: %s", e.what());
	}
}

/*
void test_bind_transaction_state() {
	diag("Test %d: Bind in different transaction states", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->sendQuery("BEGIN");
		conn->consumeInputUntilReady();

		// Prepare and bind in transaction
		conn->prepareStatement("tx_bind", "SELECT 1", true);
		PgConnection::Param param = { "1", 1 };
		conn->bindStatement("tx_bind", "", { param }, {}, true);

		conn->sendQuery("ROLLBACK");
		conn->consumeInputUntilReady();

		// Bind should still work after rollback
		conn->bindStatement("tx_bind", "", { param }, {}, true);
		ok(true, "Bind after transaction rollback succeeded");
	}
	catch (const PgException& e) {
		ok(false, "Bind in transaction state failed with error:%s", e.what());
	}
}
*/

void test_bind_named_portal() {
	diag("Test %d: Bind with named portal (should fail)", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_portal", "SELECT $1", true);

		// Attempt to bind with named portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_portal", "named_portal", { param }, {}, false);
		conn->sendSync();

		// Should get error response
		char type;
		std::vector<uint8_t> buffer;
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for named portal bind");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "0A000",
			"Received ERRCODE_FEATURE_NOT_SUPPORTED for named portal: %s",
			errormsg.c_str());
	}
	catch (const PgException& e) {
		ok(false, "Bind named portal failed with error: %s", e.what());
	}
}

void test_describe_portal() {
	diag("Test %d: Describe portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_desc_portal", "SELECT $1 AS test", true);

		// Bind with unnamed portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_desc_portal", "", { param }, {}, false);
		conn->executePortal("", 0, false);
		conn->describePortal("", false);
		conn->sendSync();

		// Verify response
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE, "Received Bind complete response");

		// Should get row description
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description for portal");

		// Verify description content
		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in description");

		if (num_fields == 1) {
			std::string name = reader.readString();
			ok(name == "test", "Field name is 'test'");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received data row for portal");
		// Verify data row
		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One column in data row (%d/1)", num_fields);
		if (num_fields == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		} else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");


		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for describe portal");
		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_UNDEFINED_CURSOR for describe portal: %s",
			errormsg.c_str());
		
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after describe portal");
	}
	catch (const PgException& e) {
		ok(false, "Describe portal failed with error: %s", e.what());
	}
}

void test_close_portal() {
	diag("Test %d: Close portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_close_portal", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_close_portal", "", { param }, {}, false);

		// Close portal
		conn->closePortal("", false);

		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received close complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");

		// Verify portal is closed
		conn->executeStatement(0, true);

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error response for closed portal");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION for closed portal: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after closed portal error");
	}
	catch (const PgException& e) {
		ok(false, "Close portal failed with error: %s", e.what());
	}
}

void test_portal_lifecycle() {
	diag("Test %d: Unnamed portal lifecycle", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_portal_life", "SELECT $1::int", true);

		// First bind
		PgConnection::Param param1 = { "10", 0 };
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);

		param1 = { "42", 0 }; // Change value for next bind
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);

		// Execute and verify
		conn->executeStatement(0, false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		do {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::DATA_ROW);

		BufferReader reader(buffer);
		int16_t num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		int32_t len = reader.readInt32();
		ok(len == 2, "Data row length is 2 (int32 size)");
		std::vector<uint8_t> val = reader.readBytes(len);
		ok(val[0] == '4' && val[1] == '2', "First execution returns 42");

		// Re-bind with new value (same statement)
		PgConnection::Param param2 = { "99", 0 };
		conn->bindStatement("stmt_portal_life", "", { param2 }, {}, false);

		// Execute again
		conn->executeStatement(0, false);
		conn->sendSync();

		// Skip to data row
		do  {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::DATA_ROW);

		reader = BufferReader(buffer);
		num_fields = reader.readInt16();
		ok(num_fields == 1, "One field in data row (%d/1)", num_fields);
		len = reader.readInt32();
		ok(len == 2, "Data row length is 2 (int32 size)");
		val = reader.readBytes(len);
		ok(val[0] == '9' && val[1] == '9', "Second execution returns 99 (bind replaced)");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE,
			"Received CommandComplete after second execution");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after second execution");

		// Close portal explicitly
		conn->closePortal("", false);
		conn->sendSync();

		conn->readMessage(type, buffer); // Close complete
		ok(type == PgConnection::CLOSE_COMPLETE, "Portal closed successfully");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after portal close");

		// Verify portal is closed
		conn->describePortal("", false);
		conn->sendSync();

		// Should get error response
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for describe closed portal");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after portal lifecycle test");

		// Auto-close on sync
		conn->bindStatement("stmt_portal_life", "", { param1 }, {}, false);
		conn->executeStatement(0, false);
		conn->sendSync();

		do {
			conn->readMessage(type, buffer);
		} while (type != PgConnection::READY_FOR_QUERY);

		
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after auto-close on sync");

		conn->describePortal("", true);
		// Should get error response again
		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for describe closed portal after auto-close");
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}
		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION after auto-close: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after describe closed portal auto-close");
		
	}
	catch (const PgException& e) {
		ok(false, "Portal lifecycle test failed: %s", e.what());
	}
}

void test_describe_closed_portal() {
	diag("Test %d: Describe closed portal", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_desc_closed", "SELECT 1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_desc_closed", "", { param }, {}, false);

		// Close portal
		conn->closePortal("", false);
		conn->sendSync();

		char type;
		std::vector<uint8_t> buffer;

		// Read bind complete
		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for closed portal");

		// Read close complete
		conn->readMessage(type, buffer);

		ok(type == PgConnection::CLOSE_COMPLETE,
			"Received close complete for portal");

		// Read ready for query
		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");


		// Describe closed portal
		conn->describePortal("", false);
		conn->sendSync();

		// Should get error
		conn->readMessage(type, buffer);

		ok(type == PgConnection::ERROR_RESPONSE,
			"Received error for closed portal describe");

		std::string errormsg;
		std::string errorcode;
		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000",
			"Received ERRCODE_INVALID_CURSOR_DEFINITION: %s",
			errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ReadyForQuery after describe closed portal");
	}
	catch (const PgException& e) {
		ok(false, "Describe closed portal failed: %s", e.what());
	}
}


void test_libpq_style_execute() {
	diag("Test %d: libpq Style Execute", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_libpq_execute", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_libpq_execute", "", { param }, {}, false);

		// describe protal
		conn->describePortal("", false);
		conn->executePortal("", 0, false);

		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description");

		BufferReader reader(buffer);
		// Read row description
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "?column?", "Field name is '?column?'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (text size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");
	

		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received Data Row");

		// Read data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1 (text size)");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		} else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");
	}
	catch (const PgException& e) {
		ok(false, "libpq Style Execute failed with error: %s", e.what());
	}
}

void test_multiple_execute_on_single_bind() {
	diag("Test %d: Multiple Execute On Single Bind", test_count++);
	auto conn = create_connection();
	if (!conn) return;

	try {
		conn->prepareStatement("stmt_mul_execute", "SELECT $1", true);

		// Bind and create portal
		PgConnection::Param param = { "1", 0 };
		conn->bindStatement("stmt_mul_execute", "", { param }, {}, false);

		conn->executePortal("", 0, false);
		conn->executePortal("", 0, false);
		// Should get close complete
		conn->sendSync();
		char type;
		std::vector<uint8_t> buffer;

		conn->readMessage(type, buffer);
		ok(type == PgConnection::BIND_COMPLETE,
			"Received bind complete for portal");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ROW_DESCRIPTION,
			"Received row description");

		BufferReader reader(buffer);
		// Read row description
		int fieldCount = reader.readInt16();
		ok(fieldCount == 1, "Row description has 1 field (%d/1)", fieldCount);
		// Read field name
		std::string fieldName = reader.readString();
		ok(fieldName == "?column?", "Field name is '?column?'");

		// Read field table OID
		unsigned int tableOid = reader.readInt32();
		ok(tableOid == 0, "Field table OID is 0 (no table)");

		// Read field attribute number
		unsigned int attrNum = reader.readInt16();
		ok(attrNum == 0, "Field attribute number is 0 (no specific column)");

		// Read field type OID
		unsigned int typeOid = reader.readInt32();
		ok(typeOid == 25, "Field type OID is 25 (text)");

		// Read field type size
		unsigned int typeSize = reader.readInt16();
		ok(typeSize == -1, "Field type size is -1 (text size)");

		// Read field type modifier
		unsigned int typeModifier = reader.readInt32();
		ok(typeModifier == -1, "Field type modifier is -1 (default)");

		// Read field format code
		unsigned int formatCode = reader.readInt16();
		ok(formatCode == 0, "Field format code is 0 (text format)");


		conn->readMessage(type, buffer);
		ok(type == PgConnection::DATA_ROW, "Received Data Row");

		// Read data row
		reader = BufferReader(buffer);
		int16_t num_columns = reader.readInt16();
		ok(num_columns == 1, "One column in data row (%d/1)", num_columns);
		if (num_columns == 1 && buffer.size() >= 5) {
			// Read column length
			int32_t column_length = reader.readInt32();
			ok(column_length == 1, "Column length is 1 (text size)");
			// Read column data
			uint8_t val = reader.readByte();
			ok(val == '1', "Column value is '1' (expected)");
		}
		else {
			ok(false, "Invalid data row size");
		}

		conn->readMessage(type, buffer);
		ok(type == PgConnection::COMMAND_COMPLETE, "Received CommandComplete");

		conn->readMessage(type, buffer);
		ok(type == PgConnection::ERROR_RESPONSE, "Received error response for malformed packet");

		std::string errormsg;
		std::string errorcode;

		if (type == PgConnection::ERROR_RESPONSE) {
			BufferReader reader(buffer);
			char field;
			while (reader.remaining() > 0 && (field = reader.readByte()) != 0) {
				if (field == 'M') errormsg = reader.readString();
				else if (field == 'C') errorcode = reader.readString();
				else reader.readString();
			}
		}

		ok(errorcode == "34000", "Received ERRCODE_UNDEFINED_CURSOR Error:%s", errormsg.c_str());

		conn->readMessage(type, buffer);
		ok(type == PgConnection::READY_FOR_QUERY,
			"Received ready for query after portal close");
	}
	catch (const PgException& e) {
		ok(false, "libpq Style Execute failed with error: %s", e.what());
	}
}

int main(int argc, char** argv) {
	if (cl.getEnv())
		return exit_status();

	plan(295); // Adjust based on number of tests

	auto admin_conn = createNewConnection(ConnType::ADMIN, "", false);

	if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
		BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
		return exit_status();
	}

	if (executeQueries(admin_conn.get(), { "SET pgsql-authentication_method=1",
										   "LOAD PGSQL VARIABLES TO RUNTIME" }) == false) {
		BAIL_OUT("Error: failed to set pgsql-authentication_method=1 in file %s, line %d", __FILE__, __LINE__);
		return exit_status();
	}

	try {
		// Parse Prepared Statement
		test_parse_without_sync();
		test_parse_with_sync(); 
		test_malformed_packet();
		test_empty_query();
		test_multiple_parse();
		test_only_sync();
		test_empty_stmt();
		//test_prepare_statment_mix();
		test_invalid_query_parse_packet();
		
		// Describe Prepared Statement
		test_describe_existing_statement();
		test_describe_nonexistent_statement();
		test_describe_without_sync();
		test_describe_malformed_packet();
		test_describe_after_close_statement();
		test_multiple_describe_calls();
		test_describe_parameter_types();
		test_describe_result_metadata();
		//test_describe_after_execute(); // FIXME: not implemented in PgConnection
		test_describe_prepared_noname();
		
		// Close Statement
		test_close_existing_statement();
		test_close_nonexistent_statement();
		test_close_unnamed_statement();
		//test_close_after_execute();
		test_close_without_sync();
		test_multiple_close_without_sync();
		test_close_malformed_packet();
		test_close_twice();
		//test_close_during_transaction();
		test_close_without_prepare();
		test_close_during_pending_ops();
		test_close_all_types();
		
		// Bind and Execute
		test_parse_execute_without_bind();
		test_bind_basic();
		test_bind_without_sync();
		test_bind_nonexistent_statement();
		test_bind_incorrect_parameters();
		test_binary_parameters();
		test_bind_large_data();
		test_bind_null_parameters();
		test_malformed_bind_packet();
		test_malformed_execute_packet();
		//test_bind_transaction_state();

		// Portals
		test_bind_named_portal(); 
		test_describe_portal(); 
		test_close_portal();   
		test_portal_lifecycle(); 
		test_describe_closed_portal();    

		// random tests
		test_libpq_style_execute();       
		test_multiple_execute_on_single_bind(); 
	}
	catch (const std::exception& e) {
		diag("Fatal error: %s",e.what());
	}

	return exit_status();
}
