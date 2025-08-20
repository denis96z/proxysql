/**
 * @file pgsql-extended_query_protocol_query_rules_test-t.cpp
 * @brief TAP test verifying ProxySQL query rules for PostgreSQL extended query protocol.
 * 
 */

#include <unistd.h>
#include <poll.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "json.hpp"

typedef unsigned int Oid;
using nlohmann::json;

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

// Helper to clear rules
void clear_rules() {
    PGConnPtr admin = createNewConnection(ADMIN);
    PQclear(PQexec(admin.get(), "DELETE FROM pgsql_query_rules"));
    PQclear(PQexec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME"));
}

// Helper to insert rule and load
void insert_rule(const std::string& sql) {
    PGConnPtr admin = createNewConnection(ADMIN);
    PGresult* res = PQexec(admin.get(), sql.c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Insert rule failed: %s\n", PQerrorMessage(admin.get()));
    }
    PQclear(res);
    res = PQexec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
    PQclear(res);
}

void delete_rule(int rule_id) {
    PGConnPtr admin = createNewConnection(ADMIN);
    std::string query = "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id);
    PGresult* res = PQexec(admin.get(), query.c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Delete rule failed: %s\n", PQerrorMessage(admin.get()));
    }
    PQclear(res);
    res = PQexec(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
    PQclear(res);
}

// Helper to get hits for rule_id
int get_hits(int rule_id) {
	std::this_thread::sleep_for(std::chrono::milliseconds(3000)); // Ensure stats are updated
    PGConnPtr admin = createNewConnection(ADMIN);
    std::string query = "SELECT hits FROM stats_pgsql_query_rules WHERE rule_id=" + std::to_string(rule_id);
    PGresult* res = PQexec(admin.get(), query.c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        PQclear(res);
        return -1; // Error
    }
    int hits = std::atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return hits;
}

// Function to perform the full flow and check hits after each step
void test_rule_flow(int rule_id, const std::string& test_name, const std::string& query, const std::string& expected_exec_result, bool expect_prepare_fail = false, bool expect_exec_fail = false, int expected_hits_after_prepare = 1, int expected_hits_after_desc = 1, int expected_hits_after_exec = 1, int expected_hits_after_close = 1) {
    PGConnPtr conn = createNewConnection(BACKEND);
    PGresult* res = PQprepare(conn.get(), "stmt", query.c_str(), 0, nullptr);
    if (expect_prepare_fail) {
        ok(PQresultStatus(res) != PGRES_COMMAND_OK, (test_name + ": Prepare failed as expected").c_str());
        PQclear(res);
        int hits = get_hits(rule_id);
        ok(hits == expected_hits_after_prepare, (test_name + ": Hits after failed prepare").c_str());

        // Skip further
        return;
    } else {
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, (test_name + ": Prepare succeeded: %s").c_str(), PQerrorMessage(conn.get()));
        PQclear(res);
        int hits_after_prepare = get_hits(rule_id);
        ok(hits_after_prepare == expected_hits_after_prepare, (test_name + ": '%d/%d' Hits after prepare").c_str(), hits_after_prepare, expected_hits_after_prepare);

        // Describe
        res = PQdescribePrepared(conn.get(), "stmt");
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, (test_name + ": Describe succeeded: %s").c_str(), PQerrorMessage(conn.get()));
        PQclear(res);
        int hits_after_desc = get_hits(rule_id);
        ok(hits_after_desc == expected_hits_after_desc, (test_name + ": '%d/%d' Hits after describe").c_str(), hits_after_desc, expected_hits_after_desc);

        // Execute
        res = PQexecPrepared(conn.get(), "stmt", 0, nullptr, nullptr, nullptr, 0);
        if (expect_exec_fail) {
            ok(PQresultStatus(res) != PGRES_TUPLES_OK, (test_name + ": Execute failed as expected").c_str());
        } else {
            ok(PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetisnull(res, 0, 0) ? "(null)" : PQgetvalue(res, 0, 0)) == expected_exec_result,
                (test_name + ": '%s/%s' Execute returned expected value").c_str(), 
                    (PQgetisnull(res, 0, 0) ? "(null)" : PQgetvalue(res, 0, 0)), expected_exec_result.c_str());
        }
        PQclear(res);
        int hits_after_exec = get_hits(rule_id);
        ok(hits_after_exec == expected_hits_after_exec, (test_name + ": '%d/%d' Hits after execute").c_str(), hits_after_exec, expected_hits_after_exec);
        
        // Close
        res = PQexec(conn.get(), "DEALLOCATE stmt");
        ok(PQresultStatus(res) == PGRES_COMMAND_OK, (test_name + ": Close succeeded: %s").c_str(), PQerrorMessage(conn.get()));
        PQclear(res);
        int hits_after_close = get_hits(rule_id);
        ok(hits_after_close == expected_hits_after_close, (test_name + ": '%d/%d' Hits after close").c_str(), hits_after_close, expected_hits_after_close);
    }
}

void consume_results(PGconn* conn) {
    PGresult* res = nullptr;
    bool saw_error = false;
    std::string errmsg;
    for (;;) {
        // Drain all immediately available results
        while ((res = PQgetResult(conn)) != nullptr) {
            ExecStatusType status = PQresultStatus(res);
            if (status == PGRES_FATAL_ERROR) {
                saw_error = true;
                errmsg = PQresultErrorMessage(res);
            }
            if (status == PGRES_PIPELINE_ABORTED) {
                // If pipeline was aborted, we need to clear the error
                saw_error = true;
                errmsg = std::string("Pipeline aborted : ") + PQresultErrorMessage(res);
            }
            PQclear(res);
        }

        if (!PQisBusy(conn)) {
            while ((res = PQgetResult(conn)) != nullptr) {
                PQclear(res);
            }
            break;  // ReadyForQuery reached
        }

        // ---- handle flushing + reading ----
        int f = PQflush(conn);
        if (f == -1) {
            throw std::runtime_error(std::string("PQflush failed: ") + PQerrorMessage(conn));
        }

        short events = POLLIN;
        if (f == 1) {
            // still data to send  also watch POLLOUT
            events |= POLLOUT;
        }

        struct pollfd pfd;
        pfd.fd = PQsocket(conn);
        pfd.events = events;
        if (pfd.fd < 0) {
            throw std::runtime_error("Invalid PostgreSQL socket");
        }

        if (poll(&pfd, 1, -1) < 0) {
            throw std::runtime_error("poll() failed");
        }

        // If socket readable  consume input
        if (pfd.revents & POLLIN) {
            if (PQconsumeInput(conn) == 0) {
                throw std::runtime_error(
                    std::string("PQconsumeInput failed: ") + PQerrorMessage(conn));
            }
        }
        // If socket writable and f==1  PQflush() will be retried on next iteration
    }

    if (saw_error) {
        throw std::runtime_error("PostgreSQL error: " + errmsg);
    }
}

void test_query_processor() {

    PGConnPtr admin_conn = createNewConnection(ADMIN);
    if (!admin_conn || PQstatus(admin_conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!backend_conn || PQstatus(backend_conn.get()) != CONNECTION_OK) {
        diag("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return;
    }

    PQsetnonblocking(backend_conn.get(), 1);
    PQenterPipelineMode(backend_conn.get());

    try {
        
        // Test 1: Parse and Sync
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (1,1,'^SELECT 1$',1)");
        int initial = get_hits(1);
        PQsendPrepare(backend_conn.get(), "", "SELECT 1", 0, NULL);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        int after = get_hits(1);
        ok((after - initial == 1), "Parse and Sync applies rule once (hits: %d/1)", after - initial);


        // Test 2: BIND EXECUTE SYNC (after Parse)
        clear_rules();
        PQsendPrepare(backend_conn.get(), "stmt2", "SELECT 1", 0, NULL);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (2,1,'^SELECT 1$',1);");
        initial = get_hits(2);
        PQsendQueryPrepared(backend_conn.get(), "stmt2", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after = get_hits(2);
        ok(after - initial == 1, "BIND EXECUTE SYNC applies rule once (hits: %d/1)", after - initial);

        // Test 3: BIND DESCRIBE EXECUTE SYNC (after Prepare)
        clear_rules();
        PQsendPrepare(backend_conn.get(), "stmt3", "SELECT 1", 0, NULL);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (3,1,'^SELECT 1$',1);");
        initial = get_hits(3);
        PQsendQueryPrepared(backend_conn.get(), "stmt3", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after = get_hits(3);
        ok(after - initial == 1, "BIND DESCRIBE EXECUTE SYNC applies rule once (hits: %d/1)", after - initial);

        // Test 4: PREPARE BIND EXECUTE PREPARE BIND EXECUTE SYNC with same query
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (4,1,'^SELECT 1$',1);");
        initial = get_hits(4);
        PQsendPrepare(backend_conn.get(), "stmt4a", "SELECT 1", 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt4a", 0, NULL, NULL, NULL, 0);
        PQsendPrepare(backend_conn.get(), "stmt4b", "SELECT 1", 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt4b", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after = get_hits(4);
        ok(after - initial == 1, "Multiple PREPARE BIND EXECUTE SYNC with same query applies rule once (hits: %d/1)", after - initial);

        // Test 5: PREPARE BIND EXECUTE PREPARE BIND EXECUTE SYNC with different queries to confirm same HG
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (5,1,'^SELECT 1$',0,1);");
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (6,1,'^SELECT 2$',200,1);");

        int initial1 = get_hits(5);
        int initial2 = get_hits(6);
        std::string query1 = "SELECT 1";
        std::string query2 = "SELECT 2";
        PQsendPrepare(backend_conn.get(), "stmt5a", query1.c_str(), 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt5a", 0, NULL, NULL, NULL, 0);
        PQsendPrepare(backend_conn.get(), "stmt5b", query2.c_str(), 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt5b", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        int after1 = get_hits(5);
        int after2 = get_hits(6);
        bool hits_once = (after1 - initial1 == 1) && (after2 - initial2 == 0);
        ok(hits_once, "Multiple message, but only first packet should run query processor. First message (%d/1) Second Message (%d/0)",
            (after1 - initial1), (after2 - initial2));

        // Test 6: Prepare Sync, then BIND EXECUTE SYNC to confirm separate pipelines apply rules separately
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (7,1,'^SELECT 1$',1);");
        initial = get_hits(7);
        PQsendPrepare(backend_conn.get(), "stmt6", "SELECT 1", 0, NULL);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after = get_hits(7);
        int initial_for_bind = after;
        PQsendQueryPrepared(backend_conn.get(), "stmt6", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        int after_bind = get_hits(7);
        ok((after - initial == 1) && (after_bind - initial_for_bind == 1), "Separate pipelines apply rules separately");

        // Test 7: BIND DESCRIBE EXECUTE SYNC with different query setup
        clear_rules();
        PQsendPrepare(backend_conn.get(), "stmt7", "SELECT 1", 0, NULL);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (8,1,'^SELECT 1$',0,1);");
        initial = get_hits(8);
        PQsendQueryPrepared(backend_conn.get(), "stmt7", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after = get_hits(8);
        ok(after - initial == 1, "BIND DESCRIBE EXECUTE SYNC applies rule once (hits: %d/1)", after - initial);
        
        // Test 8: Complex mix: PREPARE BIND EXECUTE SYNC then BIND EXECUTE PREPARE BIND EXECUTE SYNC
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (9,1,'^SELECT 1$',0,1);");
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (10,1,'^SELECT 2$',200,1);");
        initial1 = get_hits(9);
        initial2 = get_hits(10);
        PQsendPrepare(backend_conn.get(), "stmt8a", "SELECT 1", 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt8a", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
		std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Ensure pipeline is ready
        consume_results(backend_conn.get());
        PQsendQueryPrepared(backend_conn.get(), "stmt8a", 0, NULL, NULL, NULL, 0);
        PQsendPrepare(backend_conn.get(), "stmt8c", "SELECT 2", 0, NULL);
        PQsendQueryPrepared(backend_conn.get(), "stmt8c", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        consume_results(backend_conn.get());
        after1 = get_hits(9);
        after2 = get_hits(10);
        bool hits_correct = (after1 - initial1 == 2) && (after2 - initial2 == 0);  // First pipeline hits rule1 on prepare, second pipeline hits rule1 on bind (same query as first)
        ok(hits_correct, "Complex mix: hits rule1 twice (%d/2) and rule2 not at all (%d/0)", after1 - initial1, after2 - initial2);

		// Test 9: PARSE EXECUTE SYNC with SET statement
        clear_rules();
        insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (11,1,'^SELECT 1$',1);");
        initial = get_hits(11);
        PQsendPrepare(backend_conn.get(), "stmt9a", "SELECT 1", 0, NULL);
        PQsendPrepare(backend_conn.get(), "stmt9b", "SET client_min_messages = 'error'", 0, NULL);
        PQpipelineSync(backend_conn.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Ensure pipeline is ready
        consume_results(backend_conn.get());
        PQsendQueryPrepared(backend_conn.get(), "stmt9a", 0, NULL, NULL, NULL, 0);
        PQsendQueryPrepared(backend_conn.get(), "stmt9b", 0, NULL, NULL, NULL, 0);
        PQpipelineSync(backend_conn.get());
        std::this_thread::sleep_for(std::chrono::milliseconds(1000)); // Ensure pipeline is ready
        consume_results(backend_conn.get());
        consume_results(backend_conn.get());
        int exited = PQexitPipelineMode(backend_conn.get());
        ok(exited == 1, "Exited pipeline mode successfully %s", PQerrorMessage(backend_conn.get()));
        PQsetnonblocking(backend_conn.get(), 0);
        after = get_hits(11);
        ok(after - initial == 2, "PARSE EXECUTE SYNC with SET statement applies rule once (hits: %d/2)", after - initial);
		PGresult* res = PQexec(backend_conn.get(), "SHOW client_min_messages");
        const char* encoding = PQgetvalue(res, 0, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK && strcmp(encoding, "error") == 0, "client_min_messages is 'error': %s", encoding);
		PQclear(res);
    }
    catch (std::exception& ex) {
		diag("Exception in some_more_tests: %s", ex.what());
    }
}

int main(int argc, char** argv) {

    if (cl.getEnv())
        return exit_status();

    plan(101);
    
    // Test 1: Query rewrite
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (1,1,'^SELECT 1$','SELECT 2',1)");
    test_rule_flow(1, "Rewrite", "SELECT 1", "2");

    // Test 2: Query error (block with error_msg)
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, error_msg, apply) VALUES (2,1,'^SELECT 1$','blocked',1)");
    test_rule_flow(2, "Error Block", "SELECT 1", "", true, false, 1, 1, 1, 1);

    // Test 3: Query pass (no change)
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (3,1,'^SELECT 1$',1)");
    test_rule_flow(3, "Pass", "SELECT 1", "1", false, false, 1, 2, 3, 3);

    // Test 4: Query OK_msg
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, OK_msg, apply) VALUES (4,1,'^SELECT 1$','passed',1)");
    PGConnPtr conn = createNewConnection(BACKEND);
    PGresult* res = PQprepare(conn.get(), "", "SELECT 1", 0, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "OK_msg: Prepare succeeded");
        PQclear(res);
        res = PQexecPrepared(conn.get(), "", 0, nullptr, nullptr, nullptr, 0);
        //ok(PQresultStatus(res) == PGRES_COMMAND_OK, "OK_msg: Execution passed (Command Completion)"); 
        ok(PQresultStatus(res) == PGRES_TUPLES_OK, "OK_msg: Execution passed"); 
        PQclear(res);
        int hits = get_hits(4);
        ok(hits == 2, "OK_msg: '%d/2' Hits", hits);
    } else {
        ok(false, "OK_msg: Prepare failed");
    }

    // Test 5: Query routing
    clear_rules();
    // Assume HG 0 default, HG1 exists
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, destination_hostgroup, apply) VALUES (5,1,'^SELECT 10$',200,1)");
    test_rule_flow(5, "Routing", "SELECT 10", "", true,true,1);

    // Edge case 6: Unnamed statement rewrite
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (6,1,'^SELECT 1$','SELECT 3',1)");
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "", "SELECT 1", 0, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Unnamed Rewrite: Prepare succeeded");
        PQclear(res);
        res = PQexecPrepared(conn.get(), "", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetvalue(res, 0, 0)) == "3",
                "Unnamed Rewrite: Execute rewritten");
        PQclear(res);
        int hits = get_hits(6);
        ok(hits == 1, "Unnamed Rewrite: '%d/1' Hits", hits);
    } else {
        ok(false, "Unnamed Rewrite: Prepare failed");
    }

    // Edge case 7: Rewrite with parameters
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (7,1,'^SELECT \\$1 AS val$','SELECT 4 AS val',1)");
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "stmt", "SELECT $1 AS val", 1, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Param Rewrite: Prepare succeeded");
        PQclear(res);
        const char* params[1] = { "test" };
        res = PQexecPrepared(conn.get(), "stmt", 1, params, nullptr, nullptr, 0);
        ok(PQresultStatus(res) != PGRES_TUPLES_OK,
            "Param Rewrite: Execute rewritten, param failed: %s", PQerrorMessage(conn.get()));
        PQclear(res);
        int hits = get_hits(7);
        ok(hits == 1, "Param Rewrite: '%d/1' Hits", hits);
        res = PQexec(conn.get(), "DEALLOCATE stmt");
        PQclear(res);
    } else {
        ok(false, "Param Rewrite: Prepare failed");
    }

    // Edge case 8: Rewrite to invalid query
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (8,1,'^SELECT 1$','SELECT INVALID',1)");
    test_rule_flow(8, "Invalid Rewrite", "SELECT 1", "", true);

    // Edge case 9: Case insensitive match
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, re_modifiers, replace_pattern, apply) VALUES (9,1,'^select 1$','CASELESS','SELECT 5',1)");
    test_rule_flow(9, "Case Insensitive", "SELECT 1", "5");
    
    // Edge case 10: Negate match
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, negate_match_pattern, apply, flagOUT) VALUES (10,1,'^SELECT 1$',1, 0, 200)");
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply, flagIN) VALUES (11,1,'^SELECT 2$','SELECT 600',1, 200)");
    test_rule_flow(10, "Negate", "SELECT 2", "600", false, false, 1, 2, 3, 4);

    // Additional test 11: Multi-execute
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (11,1,'^SELECT 1$',1)");
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "stmt", "SELECT 1", 0, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Multi-Exec: Prepare succeeded");
        PQclear(res);
        int hits_after_prepare = get_hits(11);
        ok(hits_after_prepare == 1, "Multi-Exec: '%d/1' Hits after prepare", hits_after_prepare);
        res = PQexecPrepared(conn.get(), "stmt", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Multi-Exec: First execute succeeded");
        PQclear(res);
        int hits_after_first = get_hits(11);
        ok(hits_after_first == 2, "Multi-Exec: Hits still '%d/2' after first exec", hits_after_first);
        res = PQexecPrepared(conn.get(), "stmt", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK, "Multi-Exec: Second execute succeeded");
        PQclear(res);
        int hits_after_second = get_hits(11);
        ok(hits_after_second == 3, "Multi-Exec: Hits still '%d/3' after second exec", hits_after_second);
        res = PQexec(conn.get(), "DEALLOCATE stmt");
        PQclear(res);
    } else {
        ok(false, "Multi-Exec: Prepare failed");
    }

    // Additional test 12: Rule with username filter matching
    clear_rules();
    std::string username = cl.pgsql_username;
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, username, match_pattern, replace_pattern, apply) VALUES (12,1,'" + username + "','^SELECT 1$','SELECT 7',1)");
    test_rule_flow(12, "Username Match", "SELECT 1", "7");

    // Additional test 13: Rule with username filter not matching
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, username, match_pattern, replace_pattern, apply) VALUES (13,1,'wronguser','^SELECT 1$','SELECT 8',1)");
    test_rule_flow(13, "Username No Match", "SELECT 1", "1" /* original */, false, false, 0 /* no hit */, 0, 0, 0);

    // Additional test 14: Chain of rules - first sets flagOUT, second rewrites
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, flagOUT, apply) VALUES (14,1,'^SELECT 1$',100,0)");
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, flagIN, match_pattern, replace_pattern, apply) VALUES (15,1,100,'^SELECT 1$','SELECT 9',1)");
    // Check hits for both
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "stmt", "SELECT 1", 0, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Chain: Prepare succeeded");
        PQclear(res);
        int hits14 = get_hits(14);
        int hits15 = get_hits(15);
        ok(hits14 == 1 && hits15 == 1, "Chain: Both rules hit after prepare 14:'%d/1' 15:'%d/1'", hits14, hits15);
        res = PQexecPrepared(conn.get(), "stmt", 0, nullptr, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetvalue(res, 0, 0)) == "9",
            "Chain: Execute rewritten by second rule");
        PQclear(res);
        // Hits should not increase on exec
        ok(get_hits(14) == 1 && get_hits(15) == 1, "Chain: Hits unchanged after exec");
        res = PQexec(conn.get(), "DEALLOCATE stmt");
        PQclear(res);
    } else {
        ok(false, "Chain: Prepare failed");
    }

    // Additional test 17: Timeout rule on long query
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, timeout, apply) VALUES (17,1,'^SELECT pg_sleep\\(10\\)$',1000,1)"); // 1s timeout for 2s sleep
    test_rule_flow(17, "Timeout", "SELECT pg_sleep(10)", "", false, true, 1, 2, 3, 3);

    // Additional test 18: Parameter bind with different values
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, apply) VALUES (18,1,'^SELECT \\$1 AS val$',1)");
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "stmt", "SELECT $1 AS val", 1, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Param Bind: Prepare succeeded");
        PQclear(res);
        int hits_after_prepare = get_hits(18);
        ok(hits_after_prepare == 1, "Param Bind: '%d/1' Hits after prepare", hits_after_prepare);

        const char* param1 = "10";
        res = PQexecPrepared(conn.get(), "stmt", 1, &param1, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetvalue(res, 0, 0)) == "10",
            "Param Bind: First bind exec succeeded");

        PQclear(res);
        int hits_after_first = get_hits(18);
        ok(hits_after_first == 2, "Param Bind: Hits still '%d/2' after first", hits_after_first);

        const char* param2 = "20";
        res = PQexecPrepared(conn.get(), "stmt", 1, &param2, nullptr, nullptr, 0);
        ok(PQresultStatus(res) == PGRES_TUPLES_OK && std::string(PQgetvalue(res, 0, 0)) == "20",
            "Param Bind: Second bind exec succeeded");

        PQclear(res);
        int hits_after_second = get_hits(18);
        ok(hits_after_second == 3, "Param Bind: Hits still '%d/3' after second", hits_after_second);

        res = PQexec(conn.get(), "DEALLOCATE stmt");
        PQclear(res);

    } else {
        ok(false, "Param Bind: Prepare failed");
    }

    // Additional test 20: Error on bind after rewrite to no param
    clear_rules();
    insert_rule("INSERT INTO pgsql_query_rules (rule_id, active, match_pattern, replace_pattern, apply) VALUES (19,1,'^SELECT \\$1$','SELECT 1',1)");
    conn = createNewConnection(BACKEND);
    res = PQprepare(conn.get(), "stmt", "SELECT $1", 1, nullptr);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Rewrite No Param: Prepare succeeded");
        PQclear(res);
        const char* param = "val";
        res = PQexecPrepared(conn.get(), "stmt", 1, &param, nullptr, nullptr, 0);
        ok(PQresultStatus(res) != PGRES_TUPLES_OK, "Rewrite No Param: Exec failed due to param mismatch");

        PQclear(res);
        int hits = get_hits(19);
        ok(hits == 1, "Rewrite No Param: '%d/1' Hits", hits);
    } else {
        ok(false, "Rewrite No Param: Prepare failed");
    }

    test_query_processor();

    return exit_status();
}
