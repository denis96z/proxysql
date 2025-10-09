﻿#include "PgSQL_ExplicitTxnStateMgr.h"
#include "proxysql.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"

extern class PgSQL_Variables pgsql_variables;

PgSQL_ExplicitTxnStateMgr::PgSQL_ExplicitTxnStateMgr(PgSQL_Session* sess) : session(sess) {
	
}

PgSQL_ExplicitTxnStateMgr::~PgSQL_ExplicitTxnStateMgr() {
    for (auto& tran_state : transaction_state) {
		reset_variable_snapshot(tran_state);
    }
    transaction_state.clear();
    savepoint.clear();
}

void PgSQL_ExplicitTxnStateMgr::reset_variable_snapshot(PgSQL_Variable_Snapshot& var_snapshot) noexcept {
	for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
		if (var_snapshot.var_value[idx]) {
			free(var_snapshot.var_value[idx]);
			var_snapshot.var_value[idx] = nullptr;
		}
		var_snapshot.var_hash[idx] = 0;
	}
}

void verify_server_variables(PgSQL_Session* session) {
#ifdef DEBUG
    for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
        const char* conn_param_status = session->mybe->server_myds->myconn->get_pg_parameter_status(pgsql_tracked_variables[idx].set_variable_name);
        const char* param_value = session->mybe->server_myds->myconn->variables[idx].value;
        if (conn_param_status && param_value) {
            assert(strcmp(conn_param_status, param_value) == 0);
        }
    }
#endif
}

void PgSQL_ExplicitTxnStateMgr::start_transaction() {
    if (transaction_state.empty() == false) {
        // Transaction already started, do nothing and return
		proxy_warning("Received BEGIN command. There is already a transaction in progress\n");
        assert(session->NumActiveTransactions() > 0);
        return;
    }

    assert(session->client_myds && session->client_myds->myconn);

    PgSQL_Variable_Snapshot var_snapshot{};

    // check if already in transaction, if yes then do nothing
    for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
        
		uint32_t hash = pgsql_variables.client_get_hash(session, idx);
        if (hash != 0) {
            var_snapshot.var_hash[idx] = hash;
            var_snapshot.var_value[idx] = strdup(pgsql_variables.client_get_value(session, idx));
        } else {
            assert(idx >= PGSQL_NAME_LAST_LOW_WM); // Critical parameters/variables cannot be null
			// no need to store the value
            //var_snapshot.var_hash[idx] = 0;
            //var_snapshot.var_value[idx] = NULL;
        }
    }
    transaction_state.emplace_back(std::move(var_snapshot));
}

void PgSQL_ExplicitTxnStateMgr::commit() {
    if (transaction_state.empty()) {
        proxy_warning("Received COMMIT command. There is no transaction in progress\n");
        assert(session->NumActiveTransactions() == 0);
        return;
    }

    assert(session->client_myds && session->client_myds->myconn);
	
    for (auto& tran_state : transaction_state) {
        reset_variable_snapshot(tran_state);
    }
    transaction_state.clear();
    savepoint.clear();
    verify_server_variables(session);
}

void PgSQL_ExplicitTxnStateMgr::rollback(bool rollback_and_chain) {

    if (transaction_state.empty()) {
        proxy_warning("Received ROLLBACK command. There is no transaction in progress\n");
        assert(session->NumActiveTransactions() == 0);
        return;
    }

    assert(session->client_myds && session->client_myds->myconn);

    const PgSQL_Variable_Snapshot& var_snapshot = transaction_state.front();

    for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
        uint32_t hash = var_snapshot.var_hash[idx];
        if (hash != 0) { 
            uint32_t client_hash = pgsql_variables.client_get_hash(session, idx);
            uint32_t server_hash = pgsql_variables.server_get_hash(session, idx);

            assert(client_hash == server_hash);
            if (hash == client_hash)
                continue;

            pgsql_variables.client_set_hash_and_value(session, idx, var_snapshot.var_value[idx], hash);
            pgsql_variables.server_set_hash_and_value(session, idx, var_snapshot.var_value[idx], hash);
        } else {
            assert(idx >= PGSQL_NAME_LAST_LOW_WM); // Critical parameters/variables cannot be null
            pgsql_variables.client_reset_value(session, idx, false);
            pgsql_variables.server_reset_value(session, idx, false);
        }
    }
    // reuse of connection that has extra param set in connection
    session->client_myds->myconn->reorder_dynamic_variables_idx();
	if (session->mybe) {
		session->mybe->server_myds->myconn->reorder_dynamic_variables_idx();

        verify_server_variables(session);
	}

    // Keep the transaction state intact when executing ROLLBACK AND CHAIN
    if (rollback_and_chain == false) {
        // Clear savepoints and reset the initial snapshot
        for (auto& tran_state : transaction_state) {
            reset_variable_snapshot(tran_state);
        }
        transaction_state.clear();
    }

    savepoint.clear();
}

bool PgSQL_ExplicitTxnStateMgr::rollback_to_savepoint(std::string_view name) {
	
    if (transaction_state.empty()) {
        proxy_warning("Received ROLLBACK TO SAVEPOINT '%s' command. There is no transaction in progress\n", name.data());
        assert(session->NumActiveTransactions() == 0);
        return false;
    }
    
    assert(session->client_myds && session->client_myds->myconn);

    int tran_state_idx = -1;

    for (size_t idx = 0; idx < savepoint.size(); idx++) {
		if (savepoint[idx].size() == name.size() && 
            strncasecmp(savepoint[idx].c_str(), name.data(), name.size()) == 0) {
            tran_state_idx = idx;
			break;
		}
    }

	if (tran_state_idx == -1) {
        proxy_warning("Savepoint '%s' not found.\n", name.data());
		return false;
    };

    assert(tran_state_idx + 1 < (int)transaction_state.size());

	PgSQL_Variable_Snapshot& var_snapshot = transaction_state[tran_state_idx+1];
	for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
		uint32_t hash = var_snapshot.var_hash[idx];
		if (hash != 0) {
			uint32_t client_hash = pgsql_variables.client_get_hash(session, idx);
			uint32_t server_hash = pgsql_variables.server_get_hash(session, idx);
			assert(client_hash == server_hash);
			if (hash == client_hash)
				continue;
			pgsql_variables.client_set_hash_and_value(session, idx, var_snapshot.var_value[idx], hash);
			pgsql_variables.server_set_hash_and_value(session, idx, var_snapshot.var_value[idx], hash);
		}
		else {
			assert(idx >= PGSQL_NAME_LAST_LOW_WM); // Critical parameters/variables cannot be null
			pgsql_variables.client_reset_value(session, idx, false);
			pgsql_variables.server_reset_value(session, idx, false);
		}
	}
    
    session->client_myds->myconn->reorder_dynamic_variables_idx();
    if (session->mybe) {
        session->mybe->server_myds->myconn->reorder_dynamic_variables_idx();

        verify_server_variables(session);
    }

    for (size_t idx = tran_state_idx + 1; idx < transaction_state.size(); idx++) {
        reset_variable_snapshot(transaction_state[idx]);
    }
	transaction_state.resize(tran_state_idx + 1);
	savepoint.resize(tran_state_idx);

    return true;
}

bool PgSQL_ExplicitTxnStateMgr::release_savepoint(std::string_view name) {

    if (transaction_state.empty()) {
        proxy_warning("Received RELEASE SAVEPOINT '%s' command. There is no transaction in progress\n", name.data());
        assert(session->NumActiveTransactions() == 0);
        return false;
    }

    assert(session->client_myds && session->client_myds->myconn);

    int tran_state_idx = -1;

    for (size_t idx = 0; idx < savepoint.size(); idx++) {
        if (savepoint[idx].size() == name.size() && 
            strncasecmp(savepoint[idx].c_str(), name.data(), name.size()) == 0) {
            tran_state_idx = idx;
            break;
        }
    }

    if (tran_state_idx == -1) {
        proxy_warning("SAVEPOINT '%s' not found.\n", name.data());
        return false;
    };
    
    for (size_t idx = tran_state_idx + 1; idx < transaction_state.size(); idx++) {
        reset_variable_snapshot(transaction_state[idx]);
    }
    transaction_state.resize(tran_state_idx + 1);
    savepoint.resize(tran_state_idx);

    return true;
}

bool PgSQL_ExplicitTxnStateMgr::add_savepoint(std::string_view name) {

    if (transaction_state.empty()) {
        proxy_warning("Received SAVEPOINT '%s' command. There is no transaction in progress\n", name.data());
        assert(session->NumActiveTransactions() == 0);
        return false;
    }

    assert(session->client_myds && session->client_myds->myconn);

    auto it = std::find_if(savepoint.begin(), savepoint.end(), [name](std::string_view sp) {
        return sp.size() == name.size() &&
            strncasecmp(sp.data(), name.data(), name.size()) == 0;
        });
    if (it != savepoint.end()) return false;

    PgSQL_Variable_Snapshot var_snapshot{};

	for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
		uint32_t hash = pgsql_variables.client_get_hash(session, idx);
		if (hash != 0) {
            var_snapshot.var_hash[idx] = hash;
            var_snapshot.var_value[idx] = strdup(pgsql_variables.client_get_value(session, idx));
		}
	}
    transaction_state.emplace_back(std::move(var_snapshot));
	savepoint.emplace_back(name);
    assert((transaction_state.size() - 1) == savepoint.size());

    return true;
}

void PgSQL_ExplicitTxnStateMgr::fill_internal_session(nlohmann::json& j) {
    if (transaction_state.empty()) return;

    auto& initial_state = j["initial_state"];

    for (int idx = 0; idx < PGSQL_NAME_LAST_HIGH_WM; idx++) {
		uint32_t hash = transaction_state[0].var_hash[idx];
		if (hash != 0) {
            initial_state[pgsql_tracked_variables[idx].set_variable_name] = transaction_state[0].var_value[idx];
		}
    }

    if (savepoint.empty()) return;

    for (size_t idx = 0; idx < savepoint.size(); idx++) {
        auto& savepoint_json = j["savepoints"][savepoint[idx]];
        int tran_state_idx = idx + 1;
        for (int idx2 = 0; idx2 < PGSQL_NAME_LAST_HIGH_WM; idx2++) {
            uint32_t hash = transaction_state[tran_state_idx].var_hash[idx2];
            if (hash != 0) {
                savepoint_json[pgsql_tracked_variables[idx2].set_variable_name] = transaction_state[tran_state_idx].var_value[idx2];
            }
        }
    }
}

bool PgSQL_ExplicitTxnStateMgr::handle_transaction(std::string_view input) {
	TxnCmd cmd = tx_parser.parse(input, (session->active_transactions > 0));
    switch (cmd.type) {
    case TxnCmd::BEGIN:
        start_transaction();
        break;
    case TxnCmd::COMMIT:
        commit();
        break;
    case TxnCmd::ROLLBACK:
        rollback(false);
        break;
	case TxnCmd::ROLLBACK_AND_CHAIN:
        rollback(true);
        break;
    case TxnCmd::SAVEPOINT:
        return add_savepoint(cmd.savepoint);
    case TxnCmd::RELEASE:
        return release_savepoint(cmd.savepoint);
    case TxnCmd::ROLLBACK_TO:
        return rollback_to_savepoint(cmd.savepoint);
	default:
		// Unknown command
        return false;
    }
	return true;
}


TxnCmd PgSQL_TxnCmdParser::parse(std::string_view input, bool in_transaction_mode) noexcept {
    tokens.clear();
    TxnCmd cmd;
    bool in_quote = false;
    size_t start = 0;
    char quote_char = 0;

    // Tokenize with quote handling
    for (size_t i = 0; i <= input.size(); ++i) {
        const bool at_end = i == input.size();
        const char c = at_end ? 0 : input[i];

        if (in_quote) {
            if (c == quote_char || at_end) {
                tokens.emplace_back(input.substr(start + 1, i - start - 1));
                in_quote = false;
            }
            continue;
        }

        if (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            start = i;
        }
        else if (isspace(c) || c == ';' || at_end) {
            if (start < i) tokens.emplace_back(input.substr(start, i - start));
            start = i + 1;
        }
    }

    if (tokens.empty()) return cmd;

    size_t pos = 0;
    const std::string first = to_lower(tokens[pos++]);

    if (in_transaction_mode == true) {
        if (first == "begin") cmd.type = TxnCmd::BEGIN;
		else if (first == "start") cmd = parse_start(pos);
        else if (first == "savepoint") cmd = parse_savepoint(pos);
        else if (first == "release") cmd = parse_release(pos);
        else if (first == "rollback") cmd = parse_rollback(pos);
    } else {
        if (first == "commit" || first == "end") cmd.type = TxnCmd::COMMIT;
		else if (first == "abort") cmd.type = TxnCmd::ROLLBACK;
        else if (first == "rollback") cmd = parse_rollback(pos);
    }
    return cmd;
}

TxnCmd PgSQL_TxnCmdParser::parse_rollback(size_t& pos) noexcept {
    TxnCmd cmd{ TxnCmd::ROLLBACK };
    while (pos < tokens.size() && contains({ "work", "transaction" }, to_lower(tokens[pos]))) pos++;

    if (pos < tokens.size() && to_lower(tokens[pos]) == "to") {
        cmd.type = TxnCmd::ROLLBACK_TO;
        if (++pos < tokens.size() && to_lower(tokens[pos]) == "savepoint") pos++;
        if (pos < tokens.size()) cmd.savepoint = tokens[pos++];
    } else if (pos < tokens.size() && to_lower(tokens[pos]) == "and") {
        if (++pos < tokens.size() && to_lower(tokens[pos]) == "chain") {
            cmd.type = TxnCmd::ROLLBACK_AND_CHAIN;
			pos++;
        }
    }
    return cmd;
}

TxnCmd PgSQL_TxnCmdParser::parse_savepoint(size_t& pos) noexcept {
    TxnCmd cmd{ TxnCmd::SAVEPOINT };
    if (pos < tokens.size()) cmd.savepoint = tokens[pos++];
    return cmd;
}

TxnCmd PgSQL_TxnCmdParser::parse_release(size_t& pos) noexcept {
    TxnCmd cmd{ TxnCmd::RELEASE };
    if (pos < tokens.size() && to_lower(tokens[pos]) == "savepoint") pos++;
    if (pos < tokens.size()) cmd.savepoint = tokens[pos++];
    return cmd;
}

TxnCmd PgSQL_TxnCmdParser::parse_start(size_t& pos) noexcept {
    TxnCmd cmd{ TxnCmd::UNKNOWN };
    if (pos < tokens.size() && to_lower(tokens[pos]) == "transaction") {
        cmd.type = TxnCmd::BEGIN;
		pos++;
    }
    return cmd;
}
