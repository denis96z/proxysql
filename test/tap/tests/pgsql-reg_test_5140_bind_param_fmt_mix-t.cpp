/**
 * @file pgsql-reg_test_5140_bind_param_fmt_mix-t.cpp
 * @brief Regression test to check libpq's handling of mixed text and binary parameter.
 * 
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

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

int main(int argc, char** argv) {

    if (cl.getEnv())
        return exit_status();

    plan(2);

    auto conn = createNewConnection(BACKEND);
    if (!conn) {
        diag("connection failed");
        return 1;
    }


    // Ensure we have a test table
    PGresult* res = PQexec(conn.get(),
        "CREATE TEMP TABLE reg_test_5140 (col1 text,col2 int)"
    );
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag(PQerrorMessage(conn.get()));
        PQclear(res);
        return 1;
    }
    PQclear(res);

    // Prepare a statement with 2 parameters
    res = PQprepare(conn.get(), "stmt_test_bind_5140",
        "INSERT INTO reg_test_5140 VALUES ($1, $2)", 2, nullptr);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag(PQerrorMessage(conn.get()));
        PQclear(res);
        return 1;
    }
    PQclear(res);

    // Parameter values: 
    // col1 = "ABCDEFGHIJKLMN" (length 14)
    // col3 = NULL (-1)
    const char* values[2];
    int lengths[2];
    int formats[2];

    values[0] = "ABCDEFGHIJKLMN";  // 14 chars
    lengths[0] = 14;
    formats[0] = 0; // Text Format

    values[1] = nullptr; // NULL
    lengths[1] = -1;
    formats[1] = 1; // Binary Format

    res = PQexecPrepared(conn.get(), "stmt_test_bind_5140", 2, values, lengths, formats, 0);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        diag(PQerrorMessage(conn.get()));
        PQclear(res);
        return 1;
    }
    PQclear(res);

    // Verify row inserted as expected
    res = PQexec(conn.get(), "SELECT col1, col2 FROM reg_test_5140");
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        diag(PQerrorMessage(conn.get()));
        PQclear(res);
        return 1;
    }

    char const* c1 = PQgetvalue(res, 0, 0);
    bool isnull_c2 = PQgetisnull(res, 0, 2);

    ok(std::string(c1) == "ABCDEFGHIJKLMN", "col1 length 14 parsed correctly");
    ok(isnull_c2, "col3 NULL parsed correctly");

    PQclear(res);

    return exit_status();
}
