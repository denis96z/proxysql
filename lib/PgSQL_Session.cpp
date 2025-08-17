﻿#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON
#include <variant>
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Thread.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_utils.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "mysqld_error.h"

#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Logger.hpp"
#include "StatCounters.h"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Protocol.h"
#include "SQLite3_Server.h"
#include "PgSQL_Variables.h"
#include "ProxySQL_Cluster.hpp"
#include "PgSQL_Query_Cache.h"
#include "PgSQL_Variables_Validator.h"
#include "PgSQL_ExplicitTxnStateMgr.h"
#include "PgSQL_Extended_Query_Message.h"
#include "libinjection.h"
#include "libinjection_sqli.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32

#define SELECT_CONNECTION_ID "SELECT CONNECTION_ID()"
#define SELECT_CONNECTION_ID_LEN 22
#define SELECT_LAST_INSERT_ID "SELECT LAST_INSERT_ID()"
#define SELECT_LAST_INSERT_ID_LEN 23
#define SELECT_LAST_INSERT_ID_LIMIT1 "SELECT LAST_INSERT_ID() LIMIT 1"
#define SELECT_LAST_INSERT_ID_LIMIT1_LEN 31
#define SELECT_VARIABLE_IDENTITY "SELECT @@IDENTITY"
#define SELECT_VARIABLE_IDENTITY_LEN 17
#define SELECT_VARIABLE_IDENTITY_LIMIT1 "SELECT @@IDENTITY LIMIT 1"
#define SELECT_VARIABLE_IDENTITY_LIMIT1_LEN 25

#define EXPMARIA

const char* PROXYSQL_PS_PREFIX = "proxysql_ps_";

using std::function;
using std::vector;

/*
static inline char is_digit(char c) {
	if (c >= '0' && c <= '9')
		return 1;
	return 0;
}
static inline char is_normal_char(char c) {
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= '0' && c <= '9')
		return 1;
	if (c == '$' || c == '_')
		return 1;
	return 0;
}
*/

static const std::array<std::string,7> pgsql_critical_variables = {
	"client_encoding",
	"names",
	"datestyle",
	"intervalstyle",
	"standard_conforming_strings",
	"timezone",
	"time zone"
};

static const std::set<std::string> pgsql_other_variables = {
	"allow_in_place_tablespaces",
	"bytea_output",
	"client_min_messages",
	"enable_bitmapscan",
	"enable_hashjoin",
	"enable_indexscan",
	"enable_nestloop",
	"enable_seqscan",
	"enable_sort",
	"escape_string_warning",
	"extra_float_digits",
	"maintenance_work_mem",
	"synchronous_commit"
};

#include "proxysql_find_charset.h"

extern PgSQL_Authentication* GloPgAuth;
extern MySQL_LDAP_Authentication* GloMyLdapAuth;
extern ProxySQL_Admin* GloAdmin;
extern PgSQL_Logger* GloPgSQL_Logger;
extern PgSQL_STMT_Manager_v14* GloPgStmt;

extern SQLite3_Server* GloSQLite3Server;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication* GloClickHouseAuth;
extern ClickHouse_Server* GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */

/*
std::string proxysql_session_type_str(enum proxysql_session_type session_type) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		return "PROXYSQL_SESSION_MYSQL";d:

	} else if (session_type == PROXYSQL_SESSION_ADMIN) {
		return "PROXYSQL_SESSION_ADMIN";
	} else if (session_type == PROXYSQL_SESSION_STATS) {
		return "PROXYSQL_SESSION_STATS";
	} else if (session_type == PROXYSQL_SESSION_SQLITE) {
		return "PROXYSQL_SESSION_SQLITE";
	} else if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
		return "PROXYSQL_SESSION_CLICKHOUSE";
	} else if (session_type == PROXYSQL_SESSION_MYSQL_EMU) {
		return "PROXYSQL_SESSION_MYSQL_EMU";
	} else {
		return "PROXYSQL_SESSION_NONE";
	}
};*/

/*
Session_Regex::Session_Regex(char *p) {
	s=strdup(p);
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt=(void *)opt2;
	re=(RE2 *)new RE2(s, *opt2);
}

PgSQL_Session_Regex::~PgSQL_Session_Regex() {
	free(s);
	delete (RE2 *)re;
	delete (re2::RE2::Options *)opt;
}

bool PgSQL_Session_Regex::match(char *m) {
	bool rc=false;
	rc=RE2::PartialMatch(m,*(RE2 *)re);
	return rc;
}
*/

extern PgSQL_Query_Processor* GloPgQPro;
extern PgSQL_Query_Cache *GloPgQC;
extern ProxySQL_Admin* GloAdmin;
extern PgSQL_Threads_Handler* GloPTH;

PgSQL_Query_Info::PgSQL_Query_Info() {
	PgQueryCmd=PGSQL_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	QueryParserArgs.digest_text=NULL;
	QueryParserArgs.first_comment=NULL;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	waiting_since = 0;
	affected_rows=0;
	rows_sent=0;
	start_time=0;
	end_time=0;
	reset_extended_query_info();
}

PgSQL_Query_Info::~PgSQL_Query_Info() {
	GloPgQPro->query_parser_free(&QueryParserArgs);
	reset_extended_query_info();
}

void PgSQL_Query_Info::begin(unsigned char *_p, int len, bool header) {
	PgQueryCmd=PGSQL_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	QueryParserArgs.digest_text=NULL;
	QueryParserArgs.first_comment=NULL;
	start_time=sess->thread->curtime;
	init(_p, len, header);
	if (pgsql_thread___commands_stats || pgsql_thread___query_digests) {
		query_parser_init();
		if (pgsql_thread___commands_stats)
			query_parser_command_type();
	}
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	//waiting_since = 0;
	//affected_rows=0;
	//rows_sent=0;
}

void PgSQL_Query_Info::end() {
	query_parser_update_counters();
	query_parser_free();
	if ((end_time-start_time) > (unsigned int)pgsql_thread___long_query_time *1000) {
		__sync_add_and_fetch(&sess->thread->status_variables.stvar[st_var_queries_slow],1);
	}
	reset_extended_query_info();
}

void PgSQL_Query_Info::reset_extended_query_info() {
	extended_query_info.bind_msg = nullptr;
	extended_query_info.stmt_client_name = nullptr;
	extended_query_info.stmt_client_portal_name = nullptr;
	extended_query_info.stmt_info = nullptr;
	extended_query_info.stmt_global_id = 0;
	extended_query_info.stmt_backend_id = 0;
	extended_query_info.stmt_type = 'S';
	extended_query_info.parse_param_types.clear();
}

void PgSQL_Query_Info::init(unsigned char *_p, int len, bool header) {
	QueryLength=(header ? len-5 : len);
	QueryPointer=(header ? _p+5 : _p);
	PgQueryCmd = PGSQL_QUERY__UNINITIALIZED;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	waiting_since = 0;
	affected_rows=0;
	rows_sent=0;
	reset_extended_query_info();
}

void PgSQL_Query_Info::query_parser_init() {
	GloPgQPro->query_parser_init(&QueryParserArgs,(char *)QueryPointer,QueryLength,0);
}

enum PGSQL_QUERY_command PgSQL_Query_Info::query_parser_command_type() {
	PgQueryCmd = GloPgQPro->query_parser_command_type(&QueryParserArgs);
	return PgQueryCmd;
}

void PgSQL_Query_Info::query_parser_free() {
	GloPgQPro->query_parser_free(&QueryParserArgs);
}

unsigned long long PgSQL_Query_Info::query_parser_update_counters() {
	if (extended_query_info.stmt_info) {
		PgQueryCmd= extended_query_info.stmt_info->PgQueryCmd;
	}
	if (PgQueryCmd==PGSQL_QUERY___NONE) return 0; // this means that it was never initialized
	if (PgQueryCmd==PGSQL_QUERY__UNINITIALIZED) return 0; // this means that it was never initialized
	unsigned long long ret=GloPgQPro->query_parser_update_counters(sess, PgQueryCmd, &QueryParserArgs, end_time-start_time);
	PgQueryCmd=PGSQL_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	return ret;
}

char * PgSQL_Query_Info::get_digest_text() {
	return GloPgQPro->get_digest_text(&QueryParserArgs);
}

bool PgSQL_Query_Info::is_select_NOT_for_update() {
	if (extended_query_info.stmt_info) { // we are processing a prepared statement. We already have the information
		return extended_query_info.stmt_info->is_select_NOT_for_update;
	}
	if (QueryPointer==NULL) {
		return false;
	}
	if (bool_is_select_NOT_for_update_computed) {
		return bool_is_select_NOT_for_update;
	}
	bool_is_select_NOT_for_update_computed=true;
	if (QueryLength<7) {
		return false;
	}
	char *QP = (char *)QueryPointer;
	size_t ql = QueryLength;
	// we try to use the digest, if avaiable
	if (QueryParserArgs.digest_text) {
		QP = QueryParserArgs.digest_text;
		ql = strlen(QP);
	}
	if (strncasecmp(QP,(char *)"SELECT ",7)) {
		return false;
	}
	// if we arrive till here, it is a SELECT
	if (ql>=17) {
		char *p=QP;
		p+=ql-11;
		if (strncasecmp(p," FOR UPDATE",11)==0) {
			__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
			return false;
		}
		p=QP;
		p+=ql-10;
		if (strncasecmp(p," FOR SHARE",10)==0) {
			__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
			return false;
		}
		if (ql>=25) {
			char *p=QP;
			p+=ql-19;
			if (strncasecmp(p," LOCK IN SHARE MODE",19)==0) {
				__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
				return false;
			}
			p=QP;
			p+=ql-7;
			if (strncasecmp(p," NOWAIT",7)==0) {
				// let simplify. If NOWAIT is used, we assume FOR UPDATE|SHARE is used
				__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
				return false;
			}
			p=QP;
			p+=ql-12;
			if (strncasecmp(p," SKIP LOCKED",12)==0) {
				// let simplify. If SKIP LOCKED is used, we assume FOR UPDATE|SHARE is used
				__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
				return false;
			}
			p=QP;
			char buf[129];
			if (ql>=128) { // for long query, just check the last 128 bytes
				p+=ql-128;
				memcpy(buf,p,128);
				buf[128]=0;
			} else {
				memcpy(buf,p,ql);
				buf[ql]=0;
			}
			if (strcasestr(buf," FOR ")) {
				if (strcasestr(buf," FOR UPDATE ")) {
					__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
				if (strcasestr(buf," FOR SHARE ")) {
					__sync_fetch_and_add(&PgHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
			}
		}
	}
	bool_is_select_NOT_for_update=true;
	return true;
}

void PgSQL_Session::set_status(enum session_status e) {
	if (e == session_status___NONE) {
		if (mybe) {
			if (mybe->server_myds) {
				assert(mybe->server_myds->myconn == 0);
				if (mybe->server_myds->myconn) {
					assert(mybe->server_myds->myconn->async_state_machine == ASYNC_IDLE);
				}
			}
		}
	}
	status = e;
}


PgSQL_Session::PgSQL_Session() {
	thread_session_id = 0;
	//handler_ret = 0;
	pause_until = 0;
	qpo = new PgSQL_Query_Processor_Output();
	qpo->init();
	start_time = 0;
	command_counters = new StatCounters(15, 10);
	healthy = 1;
	autocommit = true;
	autocommit_handled = false;
	sending_set_autocommit = false;
	killed = false;
	session_type = PROXYSQL_SESSION_PGSQL;
	//admin=false;
	connections_handler = false;
	max_connections_reached = false;
	//stats=false;
	client_authenticated = false;
	default_schema = NULL;
	user_attributes = NULL;
	schema_locked = false;
	session_fast_forward = SESSION_FORWARD_TYPE_NONE;
	//started_sending_data_to_client = false;
	handler_function = NULL;
	client_myds = NULL;
	to_process = 0;
	mybe = NULL;
	mirror = false;
	mirrorPkt.ptr = NULL;
	mirrorPkt.size = 0;
	set_status(session_status___NONE);

	idle_since = 0;
	transaction_started_at = 0;

	CurrentQuery.sess = this;

	current_hostgroup = -1;
	default_hostgroup = -1;
	locked_on_hostgroup = -1;
	locked_on_hostgroup_and_all_variables_set = false;
	next_query_flagIN = -1;
	mirror_hostgroup = -1;
	mirror_flagOUT = -1;
	active_transactions = 0;

	use_ssl = false;
	change_user_auth_switch = false;

	match_regexes = NULL;
	copy_cmd_matcher = NULL;
	init(); // we moved this out to allow CHANGE_USER

	last_insert_id = 0; // #1093

	last_HG_affected_rows = -1; // #1421 : advanced support for LAST_INSERT_ID()
	proxysql_node_address = NULL;
	use_ldap_auth = false;
	transaction_state_manager = new PgSQL_ExplicitTxnStateMgr(this);
}

void PgSQL_Session::reset() {
	autocommit = true;
	autocommit_handled = false;
	sending_set_autocommit = false;
	current_hostgroup = -1;
	default_hostgroup = -1;
	locked_on_hostgroup = -1;
	locked_on_hostgroup_and_all_variables_set = false;
	if (mybes) {
		reset_all_backends();
		delete mybes;
		mybes = NULL;
	}
	mybe = NULL;

	if (session_type == PROXYSQL_SESSION_SQLITE) {
		SQLite3_Session* sqlite_sess = (SQLite3_Session*)thread->gen_args;
		if (sqlite_sess && sqlite_sess->sessdb) {
			sqlite3* db = sqlite_sess->sessdb->get_db();
			if ((*proxy_sqlite3_get_autocommit)(db) == 0) {
				sqlite_sess->sessdb->execute((char*)"COMMIT");
			}
		}
	}
	if (client_myds && client_myds->myconn) {
		client_myds->myconn->reset();
	}
}

PgSQL_Session::~PgSQL_Session() {

	//reset();

	if (locked_on_hostgroup >= 0) {
		thread->status_variables.stvar[st_var_hostgroup_locked]--;
	}

	if (client_myds) {
		if (client_authenticated) {
			switch (session_type) {
#ifdef PROXYSQLCLICKHOUSE
			case PROXYSQL_SESSION_CLICKHOUSE:
				GloClickHouseAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
				break;
#endif /* PROXYSQLCLICKHOUSE */
			default:
				if (use_ldap_auth == false) {
					GloPgAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
				}
				else {
					GloMyLdapAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->fe_username);
				}
				break;
			}
		}
		delete client_myds;
	}
	if (default_schema) {
		free(default_schema);
	}
	if (user_attributes) {
		free(user_attributes);
		user_attributes = NULL;
	}
	proxy_debug(PROXY_DEBUG_NET, 1, "Thread=%p, Session=%p -- Shutdown Session %p\n", this->thread, this, this);
	delete command_counters;
	if (session_type == PROXYSQL_SESSION_PGSQL && connections_handler == false && mirror == false) {
		__sync_fetch_and_sub(&PgHGM->status.client_connections, 1);
	}
	assert(qpo);
	delete qpo;
	match_regexes = NULL;
	copy_cmd_matcher = NULL;
	if (mirror) {
		__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
		//GloPTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
	}
	if (proxysql_node_address) {
		delete proxysql_node_address;
		proxysql_node_address = NULL;
	}
	if (transaction_state_manager)
		delete transaction_state_manager;
}

bool PgSQL_Session::handler_CommitRollback(PtrSize_t* pkt) {
	if (pkt->size <= 5) { return false; }
	char c = ((char*)pkt->ptr)[5];
	bool ret = false;
	if (c == 'c' || c == 'C') {
		if (pkt->size >= sizeof("commit") + 5) {
			if (strncasecmp((char*)"commit", (char*)pkt->ptr + 5, 6) == 0) {
				__sync_fetch_and_add(&PgHGM->status.commit_cnt, 1);
				ret = true;
			}
		}
	}
	else {
		if (c == 'r' || c == 'R') {
			if (pkt->size >= sizeof("rollback") + 5) {
				if (strncasecmp((char*)"rollback", (char*)pkt->ptr + 5, 8) == 0) {
					__sync_fetch_and_add(&PgHGM->status.rollback_cnt, 1);
					ret = true;
				}
			}
		}
	}

	if (ret == false) {
		return false;	// quick exit
	}
	// in this part of the code (as at release 2.4.3) where we call
	// NumActiveTransactions() with the check_savepoint flag .
	// This to try to handle MySQL bug https://bugs.pgsql.com/bug.php?id=107875
	//
	// Since we are limited to forwarding just one 'COMMIT|ROLLBACK', we work under the assumption that we
	// only have one active transaction. Under this premise, we should execute this command under that
	// specific connection, for that, we update 'current_hostgroup' with the first active transaction we are
	// able to find. If more transactions are simultaneously open for the session, more 'COMMIT|ROLLBACK'
	// commands are required to be issued by the client to continue ending transactions.
	int hg = FindOneActiveTransaction(true);
	if (hg != -1) {
		// there is an active transaction, we must forward the request
		current_hostgroup = hg;
		return false;
	}
	else {
		// there is no active transaction, we will just reply OK
		client_myds->DSS = STATE_QUERY_SENT_NET;
		//uint16_t setStatus = 0;
		//if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		//client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
		client_myds->myprot.generate_ok_packet(true, true, NULL, 0, (const char*)pkt->ptr + 5);
		if (mirror == false) {
			RequestEnd(NULL);
		} else {
			client_myds->DSS = STATE_SLEEP;
			status = WAITING_CLIENT_DATA;
		}
		l_free(pkt->size, pkt->ptr);
		if (c == 'c' || c == 'C') {
			__sync_fetch_and_add(&PgHGM->status.commit_cnt_filtered, 1);
		} else {
			__sync_fetch_and_add(&PgHGM->status.rollback_cnt_filtered, 1);
		}
		return true;
	}
	return false;
}


void PgSQL_Session::generate_proxysql_internal_session_json(json& j) {
	char buff[32];
	sprintf(buff, "%p", this);
	j["address"] = buff;
	if (thread) {
		sprintf(buff, "%p", thread);
		j["thread"] = buff;
	}
	const uint64_t age_ms = (thread->curtime - start_time) / 1000;
	j["age_ms"] = age_ms;
	j["status"] = status;
	j["thread_session_id"] = thread_session_id;
	j["current_hostgroup"] = current_hostgroup;
	j["default_hostgroup"] = default_hostgroup;
	j["locked_on_hostgroup"] = locked_on_hostgroup;
	j["active_transactions"] = active_transactions;
	j["transaction_time_ms"] = thread->curtime - transaction_started_at;
	j["qpo"]["create_new_connection"] = qpo->create_new_conn;
	j["qpo"]["reconnect"] = qpo->reconnect;
	j["qpo"]["sticky_conn"] = qpo->sticky_conn;
	j["qpo"]["cache_timeout"] = qpo->cache_timeout;
	j["qpo"]["cache_ttl"] = qpo->cache_ttl;
	j["qpo"]["delay"] = qpo->delay;
	j["qpo"]["destination_hostgroup"] = qpo->destination_hostgroup;
	j["qpo"]["firewall_whitelist_mode"] = qpo->firewall_whitelist_mode;
	j["qpo"]["multiplex"] = qpo->multiplex;
	j["qpo"]["timeout"] = qpo->timeout;
	j["qpo"]["retries"] = qpo->retries;
	j["qpo"]["max_lag_ms"] = qpo->max_lag_ms;
	j["user_attributes"] = (user_attributes ? user_attributes : "");
	j["transaction_persistent"] = transaction_persistent;

	transaction_state_manager->fill_internal_session(j["transaction_state"]);

	if (client_myds != NULL) { // only if client_myds is defined
		j["client"]["stream"]["pkts_recv"] = client_myds->pkts_recv;
		j["client"]["stream"]["pkts_sent"] = client_myds->pkts_sent;
		j["client"]["stream"]["bytes_recv"] = client_myds->bytes_info.bytes_recv;
		j["client"]["stream"]["bytes_sent"] = client_myds->bytes_info.bytes_sent;
		j["client"]["client_addr"]["address"] = (client_myds->addr.addr ? client_myds->addr.addr : "");
		j["client"]["client_addr"]["port"] = client_myds->addr.port;
		j["client"]["proxy_addr"]["address"] = (client_myds->proxy_addr.addr ? client_myds->proxy_addr.addr : "");
		j["client"]["proxy_addr"]["port"] = client_myds->proxy_addr.port;
		j["client"]["encrypted"] = client_myds->encrypted;
		if (client_myds->encrypted) {
			const SSL_CIPHER* cipher = SSL_get_current_cipher(client_myds->ssl);
			if (cipher) {
				const char* name = SSL_CIPHER_get_name(cipher);
				if (name) {
					j["client"]["ssl_cipher"] = name;
				}
			}
		}
		j["client"]["DSS"] = client_myds->DSS;
		j["client"]["auth_method"] = AUTHENTICATION_METHOD_STR[(int)client_myds->auth_method];
		if (client_myds->myconn != NULL) { // only if myconn is defined
			if (client_myds->myconn->userinfo != NULL) { // only if userinfo is defined
				j["client"]["userinfo"]["username"] = (client_myds->myconn->userinfo->username ? client_myds->myconn->userinfo->username : "");
				j["client"]["userinfo"]["dbname"] = (client_myds->myconn->userinfo->dbname ? client_myds->myconn->userinfo->dbname : "");
#ifdef DEBUG
				j["client"]["userinfo"]["password"] = (client_myds->myconn->userinfo->password ? client_myds->myconn->userinfo->password : "");
#endif
			}
			for (auto idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
				client_myds->myconn->variables[idx].fill_client_internal_session(j["client"], idx);
			}
			
			PgSQL_Connection* client_conn = client_myds->myconn;
			for (std::vector<uint32_t>::const_iterator it_c = client_conn->dynamic_variables_idx.begin(); 
				it_c != client_conn->dynamic_variables_idx.end(); it_c++) {
				client_conn->variables[*it_c].fill_client_internal_session(j["client"], *it_c);
			}
			//j["conn"]["no_backslash_escapes"] = client_myds->myconn->options.no_backslash_escapes;
			//j["conn"]["status"]["compression"] = client_myds->myconn->get_status(STATUS_PGSQL_CONNECTION_COMPRESSION);
			j["conn"]["ps"]["stmt_name_to_global_ids"] = client_myds->myconn->local_stmts->stmt_name_to_global_ids;
			//j["conn"]["ps"]["global_id_to_stmt_names"] = client_myds->myconn->local_stmts->global_id_to_stmt_names;

			const PgSQL_Conn_Param& conn_params = client_myds->myconn->conn_params;

			for (const auto& [key, val] : conn_params.connection_parameters) {
				j["client"]["conn"]["connection_options"][key.c_str()] = val.c_str();
			}
		}
	}
	for (unsigned int i = 0; i < mybes->len; i++) {
		PgSQL_Backend* _mybe = NULL;
		_mybe = (PgSQL_Backend*)mybes->index(i);
		j["backends"][i]["hostgroup_id"] = _mybe->hostgroup_id;
		if (_mybe->server_myds) {
			PgSQL_Data_Stream* _myds = _mybe->server_myds;
			sprintf(buff, "%p", _myds);
			j["backends"][i]["stream"]["address"] = buff;
			j["backends"][i]["stream"]["questions"] = _myds->statuses.questions;
			j["backends"][i]["stream"]["pgconnpoll_get"] = _myds->statuses.pgconnpoll_get;
			j["backends"][i]["stream"]["pgconnpoll_put"] = _myds->statuses.pgconnpoll_put;
			/* when fast_forward is not used, these metrics are always 0. Explicitly disabled
			j["backend"][i]["stream"]["pkts_recv"] = _myds->pkts_recv;
			j["backend"][i]["stream"]["pkts_sent"] = _myds->pkts_sent;
			*/
			j["backends"][i]["stream"]["bytes_recv"] = _myds->bytes_info.bytes_recv;
			j["backends"][i]["stream"]["bytes_sent"] = _myds->bytes_info.bytes_sent;
			j["backends"][i]["stream"]["DSS"] = _myds->DSS;
			if (_myds->myconn) {
				PgSQL_Connection* _myconn = _myds->myconn;
				for (auto idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
					_myconn->variables[idx].fill_server_internal_session(j["backends"], i, idx);
				}
				for (std::vector<uint32_t>::const_iterator it_c = _myconn->dynamic_variables_idx.begin(); it_c != _myconn->dynamic_variables_idx.end(); it_c++) {
					_myconn->variables[*it_c].fill_server_internal_session(j["backends"], i, *it_c);
				}
				sprintf(buff, "%p", _myconn);
				j["backends"][i]["conn"]["address"] = buff;
				j["backends"][i]["conn"]["auto_increment_delay_token"] = _myconn->auto_increment_delay_token;
				j["backends"][i]["conn"]["bytes_recv"] = _myconn->bytes_info.bytes_recv;
				j["backends"][i]["conn"]["bytes_sent"] = _myconn->bytes_info.bytes_sent;
				j["backends"][i]["conn"]["questions"] = _myconn->statuses.questions;
				j["backends"][i]["conn"]["pgconnpoll_get"] = _myconn->statuses.pgconnpoll_get;
				j["backends"][i]["conn"]["pgconnpoll_put"] = _myconn->statuses.pgconnpoll_put;
				//j["backend"][i]["conn"]["charset"] = _myds->myconn->options.charset; // not used for backend
				//j["backends"][i]["conn"]["session_track_gtids"] = (_myconn->options.session_track_gtids ? _myconn->options.session_track_gtids : "");
				j["backends"][i]["conn"]["init_connect"] = (_myconn->options.init_connect ? _myconn->options.init_connect : "");
				j["backends"][i]["conn"]["init_connect_sent"] = _myds->myconn->options.init_connect_sent;
				//j["backends"][i]["conn"]["standard_conforming_strings"] = _myconn->options.no_backslash_escapes;
				j["backends"][i]["conn"]["status"]["advisory_lock"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
				j["backends"][i]["conn"]["status"]["advisory_xact_lock"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK);
				j["backends"][i]["conn"]["status"]["lock_tables"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_LOCK_TABLES);
				j["backends"][i]["conn"]["status"]["has_savepoint"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
				j["backends"][i]["conn"]["status"]["temporary_table"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE);
				j["backends"][i]["conn"]["status"]["user_variable"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_USER_VARIABLE);
				j["backends"][i]["conn"]["status"]["no_multiplex"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
				j["backends"][i]["conn"]["status"]["no_multiplex_HG"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG);
				j["backends"][i]["conn"]["status"]["has_sequences"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_HAS_SEQUENCES);
				//j["backends"][i]["conn"]["status"]["compression"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_COMPRESSION);
				j["backends"][i]["conn"]["status"]["prepared_statement"] = _myconn->get_status(STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT);
				{
					// MultiplexDisabled : status returned by PgSQL_Connection::MultiplexDisabled();
					// MultiplexDisabled_ext : status returned by PgSQL_Connection::MultiplexDisabled() || PgSQL_Connection::isActiveTransaction()
					bool multiplex_disabled = _myconn->MultiplexDisabled();
					j["backends"][i]["conn"]["MultiplexDisabled"] = multiplex_disabled;
					if (multiplex_disabled == false) {
						if (_myconn->IsActiveTransaction() == true) {
							multiplex_disabled = true;
						}
					}
					j["backends"][i]["conn"]["MultiplexDisabled_ext"] = multiplex_disabled;
				}
				j["backends"][i]["conn"]["ps"]["backend_stmt_to_global_ids"] = _myconn->local_stmts->backend_stmt_to_global_ids;
				j["backends"][i]["conn"]["ps"]["global_stmt_to_backend_ids"] = _myconn->local_stmts->global_stmt_to_backend_ids;
				//j["backends"][i]["conn"]["client_flag"]["value"] = _myconn->options.client_flag;
				//j["backends"][i]["conn"]["client_flag"]["client_found_rows"] = (_myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
				//j["backends"][i]["conn"]["client_flag"]["client_multi_statements"] = (_myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
				//j["backends"][i]["conn"]["client_flag"]["client_deprecate_eof"] = (_myconn->options.client_flag & CLIENT_DEPRECATE_EOF ? 1 : 0);
				if (_myconn->is_connected()) {
					sprintf(buff, "%p", _myconn->get_pg_connection());
					j["backends"][i]["conn"]["pgsql"]["address"] = buff;
					j["backends"][i]["conn"]["pgsql"]["host"] = _myconn->get_pg_host();
					j["backends"][i]["conn"]["pgsql"]["host_addr"] = _myconn->get_pg_hostaddr();
					j["backends"][i]["conn"]["pgsql"]["port"] = _myconn->get_pg_port();
					j["backends"][i]["conn"]["pgsql"]["user"] = _myconn->get_pg_user();
#ifdef DEBUG
					j["backends"][i]["conn"]["pgsql"]["password"] = _myconn->get_pg_password();
#endif
					j["backends"][i]["conn"]["pgsql"]["database"] = _myconn->get_pg_dbname();
					j["backends"][i]["conn"]["pgsql"]["backend_pid"] = _myconn->get_pg_backend_pid();
					j["backends"][i]["conn"]["pgsql"]["using_ssl"] = _myconn->get_pg_ssl_in_use() ? "YES" : "NO";
					j["backends"][i]["conn"]["pgsql"]["error_msg"] = _myconn->get_pg_error_message();
					j["backends"][i]["conn"]["pgsql"]["options"] = _myconn->get_pg_options();
					j["backends"][i]["conn"]["pgsql"]["fd"] = _myconn->get_pg_socket_fd();
					j["backends"][i]["conn"]["pgsql"]["protocol_version"] = _myconn->get_pg_protocol_version();
					j["backends"][i]["conn"]["pgsql"]["server_version"] = _myconn->get_pg_server_version_str(buff, sizeof(buff));
					j["backends"][i]["conn"]["pgsql"]["transaction_status"] = _myconn->get_pg_transaction_status_str();
					j["backends"][i]["conn"]["pgsql"]["connection_status"] = _myconn->get_pg_connection_status_str();
					j["backends"][i]["conn"]["pgsql"]["client_encoding"] = _myconn->get_pg_client_encoding();
					j["backends"][i]["conn"]["pgsql"]["is_nonblocking"] = _myconn->get_pg_is_nonblocking() ? "YES" : "NO";
				}
			}
		}
	}
}

bool PgSQL_Session::handler_special_queries(PtrSize_t* pkt, bool* lock_hostgroup) {

	if (pkt->size > (5 + 18) && strncasecmp((char*)"PROXYSQL INTERNAL ", (char*)pkt->ptr + 5, 18) == 0) {
		return_proxysql_internal(pkt);
		return true;
	}
	if (locked_on_hostgroup == -1) {
		if (handler_CommitRollback(pkt) == true) {
			return true;
		}
	} else {
		if (strncasecmp((char*)"SET ", (char*)pkt->ptr + 5, 4) == 0 ||
			strncasecmp((char*)"RESET ", (char*)pkt->ptr + 5, 6) == 0) {
			// this is a circuit breaker, we will send everything to the backend
			//
			// also note that in the current implementation we stop tracking variables:
			// this becomes a problem if pgsql-set_query_lock_on_hostgroup is
			// disabled while a session is already locked
			return false;
		}
	}
	/*
	//handle 2564
	if (pkt->size == SELECT_VERSION_COMMENT_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncmp((char*)SELECT_VERSION_COMMENT, (char*)pkt->ptr + 5, pkt->size - 5) == 0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		PtrSize_t pkt_2;
		if (deprecate_eof_active) {
			pkt_2.size = PROXYSQL_VERSION_COMMENT_WITH_OK_LEN;
			pkt_2.ptr = l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr, PROXYSQL_VERSION_COMMENT_WITH_OK, pkt_2.size);
		}
		else {
			pkt_2.size = PROXYSQL_VERSION_COMMENT_LEN;
			pkt_2.ptr = l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr, PROXYSQL_VERSION_COMMENT, pkt_2.size);
		}
		status = WAITING_CLIENT_DATA;
		client_myds->DSS = STATE_SLEEP;
		client_myds->PSarrayOUT->add(pkt_2.ptr, pkt_2.size);
		if (mirror == false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size, pkt->ptr);
		return true;
	}
	if (pkt->size == strlen((char*)"select USER()") + 5 && strncmp((char*)"select USER()", (char*)pkt->ptr + 5, pkt->size - 5) == 0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		char* query1 = (char*)"SELECT \"%s\" AS 'USER()'";
		char* query2 = (char*)malloc(strlen(query1) + strlen(client_myds->myconn->userinfo->username) + 10);
		sprintf(query2, query1, client_myds->myconn->userinfo->username);
		char* error;
		int cols;
		int affected_rows;
		SQLite3_result* resultset;
		GloAdmin->admindb->execute_statement(query2, &error, &cols, &affected_rows, &resultset);
		SQLite3_to_MySQL(resultset, error, affected_rows, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		free(query2);
		if (mirror == false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size, pkt->ptr);
		return true;
	}
	// MySQL client check command for dollars quote support, starting at version '8.1.0'. See #4300.
	if ((pkt->size == strlen("SELECT $$") + 5) && strncasecmp("SELECT $$", (char*)pkt->ptr + 5, pkt->size - 5) == 0) {
		pair<int, const char*> err_info{ get_dollar_quote_error(pgsql_thread___server_version) };

		client_myds->DSS = STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 1, err_info.first, (char*)"HY000", err_info.second, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;

		if (mirror == false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size, pkt->ptr);

		return true;
	}*/

	// 'LOAD DATA LOCAL INFILE' is unsupported. We report an specific error to inform clients about this fact. For more context see #833.
	if ((pkt->size >= 22 + 5) && (strncasecmp((char*)"LOAD DATA LOCAL INFILE", (char*)pkt->ptr + 5, 22) == 0)) {
		if (pgsql_thread___enable_load_data_local_infile == false) {
			client_myds->DSS = STATE_QUERY_SENT_NET;
			client_myds->myprot.generate_error_packet(true, true, "Unsupported 'LOAD DATA LOCAL INFILE' command", 
				PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, false, true);
			if (mirror == false) {
				RequestEnd(NULL);
			}
			else {
				client_myds->DSS = STATE_SLEEP;
				status = WAITING_CLIENT_DATA;
			}
			l_free(pkt->size, pkt->ptr);
			return true;
		}
		else {
			if (pgsql_thread___verbose_query_error) {
				proxy_warning(
					"Command '%.*s' refers to file in ProxySQL instance, NOT on client side!\n",
					static_cast<int>(pkt->size - sizeof(mysql_hdr) - 1),
					static_cast<char*>(pkt->ptr) + 5
				);
			}
			else {
				proxy_warning(
					"Command 'LOAD DATA LOCAL INFILE' refers to file in ProxySQL instance, NOT on client side!\n"
				);
			}
		}
	}

	return false;
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session() {
	if (pkt.size < 15 * 1024 * 1024 && (qpo->mirror_hostgroup >= 0 || qpo->mirror_flagOUT >= 0)) {
		// check if there are too many mirror sessions in queue
		if (thread->mirror_queue_mysql_sessions->len >= (unsigned int)pgsql_thread___mirror_max_queue_length) {
			return;
		}
		// at this point, we will create the new session
		// we will later decide if queue it or sent it immediately

//		int i=0;
//		for (i=0;i<100;i++) {
		PgSQL_Session* newsess = NULL;
		if (thread->mirror_queue_mysql_sessions_cache->len == 0) {
			newsess = new PgSQL_Session();
			newsess->client_myds = new PgSQL_Data_Stream();
			newsess->client_myds->DSS = STATE_SLEEP;
			newsess->client_myds->sess = newsess;
			newsess->client_myds->fd = 0;
			newsess->client_myds->myds_type = MYDS_FRONTEND;
			newsess->client_myds->PSarrayOUT = new PtrSizeArray();
			newsess->thread_session_id = __sync_fetch_and_add(&glovars.thread_id, 1);
			if (newsess->thread_session_id == 0) {
				newsess->thread_session_id = __sync_fetch_and_add(&glovars.thread_id, 1);
			}
			newsess->status = WAITING_CLIENT_DATA;
			PgSQL_Connection* myconn = new PgSQL_Connection(true);
			newsess->client_myds->attach_connection(myconn);
			newsess->client_myds->myprot.init(&newsess->client_myds, newsess->client_myds->myconn->userinfo, newsess);
			newsess->mirror = true;
			newsess->client_myds->destroy_queues();
		}
		else {
			newsess = (PgSQL_Session*)thread->mirror_queue_mysql_sessions_cache->remove_index_fast(0);
		}
		newsess->client_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		newsess->to_process = 1;
		newsess->default_hostgroup = default_hostgroup;
		if (qpo->mirror_hostgroup >= 0) {
			newsess->mirror_hostgroup = qpo->mirror_hostgroup; // in the new session we copy the mirror hostgroup
		}
		else {
			newsess->mirror_hostgroup = default_hostgroup; // copy the default
		}
		newsess->mirror_flagOUT = qpo->mirror_flagOUT; // in the new session we copy the mirror flagOUT
		if (newsess->default_schema == NULL) {
			newsess->default_schema = strdup(default_schema);
		}
		else {
			if (strcmp(newsess->default_schema, default_schema)) {
				free(newsess->default_schema);
				newsess->default_schema = strdup(default_schema);
			}
		}
		newsess->mirrorPkt.size = pkt.size;
		newsess->mirrorPkt.ptr = l_alloc(newsess->mirrorPkt.size);
		memcpy(newsess->mirrorPkt.ptr, pkt.ptr, pkt.size);

		if (thread->mirror_queue_mysql_sessions->len == 0) {
			// there are no sessions in the queue, we try to execute immediately
			// Only pgsql_thread___mirror_max_concurrency mirror session can run in parallel
			if (__sync_add_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1) > (unsigned int)pgsql_thread___mirror_max_concurrency) {
				// if the limit is reached, we queue it instead
				__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
				thread->mirror_queue_mysql_sessions->add(newsess);
			}
			else {
				//GloPTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Increment();
				thread->register_session(thread,newsess);
				newsess->handler(); // execute immediately
				//newsess->to_process=0;
				if (newsess->status == WAITING_CLIENT_DATA) { // the mirror session has completed
					thread->unregister_session(thread->mysql_sessions->len - 1);
					unsigned int l = (unsigned int)pgsql_thread___mirror_max_concurrency;
					if (thread->mirror_queue_mysql_sessions->len * 0.3 > l) l = thread->mirror_queue_mysql_sessions->len * 0.3;
					if (thread->mirror_queue_mysql_sessions_cache->len <= l) {
						bool to_cache = true;
						if (newsess->mybe) {
							if (newsess->mybe->server_myds) {
								to_cache = false;
							}
						}
						if (to_cache) {
							__sync_sub_and_fetch(&GloPTH->status_variables.mirror_sessions_current, 1);
							//GloPTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
							thread->mirror_queue_mysql_sessions_cache->add(newsess);
						}
						else {
							delete newsess;
						}
					}
					else {
						delete newsess;
					}
				}
			}
		}
		else {
			thread->mirror_queue_mysql_sessions->add(newsess);
		}
	}
}

int PgSQL_Session::handler_again___status_PINGING_SERVER() {
	assert(mybe->server_myds->myconn);
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	int rc = myconn->async_ping(myds->revents);
	if (rc == 0) {
		myconn->async_state_machine = ASYNC_IDLE;
		myconn->compute_unknown_transaction_status();
		//if (pgsql_thread___multiplexing && (myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
		// due to issue #2096 we disable the global check on pgsql_thread___multiplexing
		if ((myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
			myds->return_MySQL_Connection_To_Pool();
		} else {
			myds->destroy_MySQL_Connection_From_Pool(true);
		}
		delete mybe->server_myds;
		mybe->server_myds = NULL;
		set_status(session_status___NONE);
		return -1;
	}
	else {
		if (rc == -1 || rc == -2) {
			if (rc == -2) {
				unsigned long long us = pgsql_thread___ping_timeout_server * 1000;
				us += thread->curtime;
				us -= myds->wait_until;
				proxy_error("Ping timeout during ping on %s:%d after %lluus (timeout %dms)\n", myconn->parent->address, myconn->parent->port, us, pgsql_thread___ping_timeout_server);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_PING_TIMEOUT);
			}
			else { // rc==-1
				int myerr = 0; // TODO: fix this mysql_errno(myconn->pgsql);
				detected_broken_connection(__FILE__, __LINE__, __func__, "during ping", myconn,  true);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr);
			}
			myds->destroy_MySQL_Connection_From_Pool(false);
			myds->fd = 0;
			delete mybe->server_myds;
			mybe->server_myds = NULL;
			return -1;
		}
		else {
			// rc==1 , nothing to do for now
			if (myds->mypolls == NULL) {
				thread->mypolls.add(POLLIN | POLLOUT, myds->fd, myds, thread->curtime);
			}
		}
	}
	return 0;
}

int PgSQL_Session::handler_again___status_RESETTING_CONNECTION() {
	assert(mybe->server_myds->myconn);
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	if (myds->mypolls == NULL) {
		thread->mypolls.add(POLLIN | POLLOUT, myds->fd, myds, thread->curtime);
	}
	myds->DSS = STATE_MARIADB_QUERY;
	
	int rc = myconn->async_reset_session(myds->revents);
	if (rc == 0) {
		__sync_fetch_and_add(&PgHGM->status.backend_reset_connection, 1);
		myds->myconn->reset();
		PgHGM->increase_reset_counter();
		myds->DSS = STATE_MARIADB_GENERIC;
		myconn->async_state_machine = ASYNC_IDLE;
		myds->return_MySQL_Connection_To_Pool();
		delete mybe->server_myds;
		mybe->server_myds = NULL;
		set_status(session_status___NONE);
		return -1;
	} else {
		if (rc == -1 || rc == -2) {
			if (rc == -2) {
				proxy_error("Resetting Connection timeout during Reset Session on %s , %d\n", myconn->parent->address, myconn->parent->port);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_CHANGE_USER_TIMEOUT);
			} else { // rc==-1
				const bool error_present = myconn->is_error_present();
				PgHGM->p_update_pgsql_error_counter(
					p_pgsql_error_type::pgsql,
					myconn->parent->myhgc->hid,
					myconn->parent->address,
					myconn->parent->port,
					(error_present ? 9999 : ER_PROXYSQL_OFFLINE_SRV) // TOFIX: 9999 is a placeholder for the actual error code
				);
				if (error_present) {
					proxy_error("Detected an error during Reset Session on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myconn->get_error_code_with_message().c_str());
				} else {
					proxy_error(
						"Detected an error during Reset Session on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n",
						myconn->parent->myhgc->hid,
						myconn->parent->address,
						myconn->parent->port,
						myds->fd,
						myds->myconn->fd,
						ER_PROXYSQL_OFFLINE_SRV,
						"Detected offline server prior to statement execution"
					);
				}
			}
			myds->destroy_MySQL_Connection_From_Pool(false);
			myds->fd = 0;
			RequestEnd(myds); //fix bug #682
			return -1;
		} else {
			// rc==1 , nothing to do for now
			if (myds->mypolls == NULL) {
				thread->mypolls.add(POLLIN | POLLOUT, myds->fd, myds, thread->curtime);
			}
		}
	}
	return 0;
}

void PgSQL_Session::handler_again___new_thread_to_cancel_query() {
	PgSQL_Data_Stream* myds = mybe->server_myds;
	if (myds->myconn) {
		if (myds->killed_at == 0) {
			myds->wait_until = 0;
			myds->killed_at = thread->curtime;

			const PgSQL_Connection_userinfo* ui = client_myds->myconn->userinfo;
			std::unique_ptr<PgSQL_CancelQueryArgs> ka = std::make_unique<PgSQL_CancelQueryArgs>((PGconn*)myds->myconn->get_pg_connection(), ui->username,
				myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->parent->myhgc->hid, myds->myconn->get_backend_pid(), thread);
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_attr_setstacksize(&attr, 256 * 1024);
			pthread_t pt;
			if (pthread_create(&pt, &attr, &PgSQL_cancel_query_thread, ka.release()) != 0) {
				// LCOV_EXCL_START
				proxy_error("Thread creation\n");
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
	}
}

// NEXT_IMMEDIATE is a legacy macro used inside handler() to immediately jump
// to handler_again
#define NEXT_IMMEDIATE(new_st) do { set_status(new_st); goto handler_again; } while (0)
// NEXT_IMMEDIATE_NEW is a new macro to use *outside* handler().
// handler() should check the return code of the function it calls, and if
// true should jump to handler_again
#define NEXT_IMMEDIATE_NEW(new_st) do { set_status(new_st); return true; } while (0)

bool PgSQL_Session::handler_again___verify_init_connect() {
	if (mybe->server_myds->myconn->options.init_connect_sent == false) {
		// we needs to set it to true
		mybe->server_myds->myconn->options.init_connect_sent = true;
		char* tmp_init_connect = pgsql_thread___init_connect;
		char* init_connect_hg = mybe->server_myds->myconn->parent->myhgc->attributes.init_connect;
		if (init_connect_hg != NULL && strlen(init_connect_hg) != 0) {
			// mysql_hostgroup_attributes takes priority
			tmp_init_connect = init_connect_hg;
		}
		if (tmp_init_connect) {
			// we send init connect queries only if set
			mybe->server_myds->myconn->options.init_connect = strdup(tmp_init_connect);
			// Sets the previous status of the PgSQL session according to the current status.
			set_previous_status_mode3();
			NEXT_IMMEDIATE_NEW(SETTING_INIT_CONNECT);
		}
	}
	return false;
}

bool PgSQL_Session::handler_again___verify_backend_user_db() {
	PgSQL_Data_Stream* myds = mybe->server_myds;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->username, mybe->server_myds->myconn->userinfo->username);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->dbname, mybe->server_myds->myconn->userinfo->dbname);
	if (client_myds->myconn->userinfo->hash != mybe->server_myds->myconn->userinfo->hash) {
		assert(strcmp(client_myds->myconn->userinfo->username, myds->myconn->userinfo->username) == 0);
		assert(strcmp(client_myds->myconn->userinfo->dbname, myds->myconn->userinfo->dbname) == 0);
	}
	// if we reach here, the username is the same
	if (myds->myconn->requires_RESETTING_CONNECTION(client_myds->myconn)) {
		// if we reach here, even if the username is the same,
		// the backend connection has some session variable set
		// that the client never asked for
		// because we can't unset variables, we will reset the connection
		// 
		// Sets the previous status of the PgSQL session according to the current status.
		set_previous_status_mode3();
		mybe->server_myds->wait_until = thread->curtime + pgsql_thread___connect_timeout_server * 1000;   // max_timeout
		NEXT_IMMEDIATE_NEW(RESETTING_CONNECTION_V2);
	}
	return false;
}

bool PgSQL_Session::handler_again___status_SETTING_INIT_CONNECT(int* _rc) {
	bool ret = false;
	assert(mybe->server_myds->myconn);
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	myds->DSS = STATE_MARIADB_QUERY;
	enum session_status st = status;
	if (myds->mypolls == NULL) {
		thread->mypolls.add(POLLIN | POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc = myconn->async_send_simple_command(myds->revents, myconn->options.init_connect, strlen(myconn->options.init_connect));
	if (rc == 0) {
		myds->revents |= POLLOUT;	// we also set again POLLOUT to send a query immediately!
		//myds->free_mysql_real_query();
		myds->DSS = STATE_MARIADB_GENERIC;
		st = previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	}
	else {
		if (rc == -1 || rc == -2) {
			// the command failed
			int myerr = 0; // TODO: fix this mysql_errno(myconn->pgsql);
			PgHGM->p_update_pgsql_error_counter(
				p_pgsql_error_type::pgsql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				(myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV)
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn = false;
				// client error, serious
				detected_broken_connection(__FILE__, __LINE__, __func__, "while setting INIT CONNECT", myconn);
				//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				if (rc != -2) { // see PMC-10003
					if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
						retry_conn = true;
					}
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd = 0;
				if (rc == -2) {
					// Here we handle PMC-10003
					// and we terminate the session
					retry_conn = false;
				}
				if (retry_conn) {
					myds->DSS = STATE_NOT_INITIALIZED;
					//previous_status.push(PROCESSING_QUERY);
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc = -1;	// an error happened, we should destroy the Session
				return ret;
			}
			else {
				proxy_warning("Error while setting INIT CONNECT on %s:%d hg %d : %d, %d\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, 9999);
				// we won't go back to PROCESSING_QUERY
				st = previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate, "%s", ""/* TODO: fix this mysql_sqlstate(myconn->pgsql)*/);
				client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 1, 9999 /* TODO: fix this mysql_errno(myconn->pgsql)*/, sqlstate, "" /* TODO: fix this mysql_error(myconn->pgsql)*/);
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd = 0;
				status = WAITING_CLIENT_DATA;
				client_myds->DSS = STATE_SLEEP;
			}
		}
		else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool PgSQL_Session::handler_again___status_SETTING_GENERIC_VARIABLE(int* _rc, const char* var_name, const char* var_value, 
	bool no_quote, bool set_transaction) {
	bool ret = false;
	assert(mybe->server_myds->myconn);
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	myds->DSS = STATE_MARIADB_QUERY;
	enum session_status st = status;
	if (myds->mypolls == NULL) {
		thread->mypolls.add(POLLIN | POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	char* query = NULL;
	unsigned long query_length = 0;
	if (myconn->async_state_machine == ASYNC_IDLE) {
		char* q = NULL;
		if (set_transaction == false) {
			if (no_quote) {
				q = (char*)"SET %s TO %s";
			}
			else {
				q = (char*)"SET %s TO '%s'"; // default
				if (var_value[0] && var_value[0] == '@') {
					q = (char*)"SET %s TO %s";
				}
				if (strncasecmp(var_value, (char*)"CONCAT", 6) == 0)
					q = (char*)"SET %s TO %s";
				if (strncasecmp(var_value, (char*)"IFNULL", 6) == 0)
					q = (char*)"SET %s TO %s";
				if (strncasecmp(var_value, (char*)"REPLACE", 7) == 0)
					q = (char*)"SET %s TO %s";
				if (var_value[0] && var_value[0] == '(') { // the value is a subquery
					q = (char*)"SET %s TO %s";
				}
			}
		}
		else {
			// NOTE: for now, only SET SESSION is supported
			// the calling function is already passing "SESSION TRANSACTION"
			q = (char*)"SET %s %s";
		}
		query = (char*)malloc(strlen(q) + strlen(var_name) + strlen(var_value));
		sprintf(query, q, var_name, var_value);
		query_length = strlen(query);
	}
	int rc = myconn->async_send_simple_command(myds->revents, query, query_length);
	if (query) {
		free(query);
		query = NULL;
	}
	if (rc == 0) {
		if (strncasecmp(var_name, "client_encoding", sizeof("client_encoding")-1) == 0) {
			__sync_fetch_and_add(&PgHGM->status.backend_set_client_encoding, 1);
		}
		myds->revents |= POLLOUT;	// we also set again POLLOUT to send a query immediately!
		myds->DSS = STATE_MARIADB_GENERIC;
		st = previous_status.top();
		previous_status.pop();

		/*if (strcasecmp("transaction isolation level", var_name) == 0) {
			pgsql_variables.server_reset_value(this, SQL_NEXT_ISOLATION_LEVEL);
			pgsql_variables.client_reset_value(this, SQL_NEXT_ISOLATION_LEVEL);
		} else if (strcasecmp("transaction read", var_name) == 0) {
			pgsql_variables.server_reset_value(this, SQL_NEXT_TRANSACTION_READ);
			pgsql_variables.client_reset_value(this, SQL_NEXT_TRANSACTION_READ);
		}*/

		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc == -1) {
			// the command failed
			bool error_present = myconn->is_error_present();
			PgHGM->p_update_pgsql_error_counter(
				p_pgsql_error_type::pgsql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				(error_present ? 9999 : ER_PROXYSQL_OFFLINE_SRV) // TOFIX: 9999 is a placeholder for the actual error code
			);
			if (error_present == false || (error_present == true && myconn->is_connection_in_reusable_state() == false)) {
				bool retry_conn = false;
				// client error, serious
				detected_broken_connection(__FILE__, __LINE__, __func__, "while setting ", myconn);
				if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
					retry_conn = true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd = 0;
				if (retry_conn) {
					myds->DSS = STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc = -1;
				return false;
			} else {
				proxy_warning("Error while setting %s to \"%s\" on %s:%d hg %d: %s\n", var_name, var_value, myconn->parent->address, myconn->parent->port, current_hostgroup, myconn->get_error_code_with_message().c_str());

				if (myconn->get_error_code() == PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR ||
					myconn->get_error_code() == PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_PARAMETER ||
					myconn->get_error_code() == PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_OBJECT) {
					
					int idx = PGSQL_NAME_LAST_HIGH_WM;
					for (int i = PGSQL_NAME_LAST_LOW_WM + 1; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
						if (variable_name_exists(pgsql_tracked_variables[i], var_name) == true) {
							idx = i;
							break;
						}
					}
					if (idx != PGSQL_NAME_LAST_HIGH_WM) {
						myconn->var_absent[idx] = true;

						myds->myconn->async_free_result();
						myconn->compute_unknown_transaction_status();

						myds->revents |= POLLOUT;	// we also set again POLLOUT to send a query immediately!
						myds->DSS = STATE_MARIADB_GENERIC;
						st = previous_status.top();
						previous_status.pop();
						NEXT_IMMEDIATE_NEW(st);
					}
				}

				// we won't go back to PROCESSING_QUERY
				st = previous_status.top();
				previous_status.pop();
				client_myds->myprot.generate_error_packet(true, true, myconn->get_error_message().c_str(), myconn->get_error_code(), false);
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd = 0;
				RequestEnd(myds); //fix bug #682
				ret = true;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool PgSQL_Session::handler_again___status_CONNECTING_SERVER(int* _rc) {
	//fprintf(stderr,"CONNECTING_SERVER\n");
	unsigned long long curtime = monotonic_time();
	thread->atomic_curtime = curtime;
	if (mirror) {
		mybe->server_myds->connect_retries_on_failure = 0; // no try for mirror
		mybe->server_myds->wait_until = thread->curtime + pgsql_thread___connect_timeout_server * 1000;
		pause_until = 0;
	}
	if (mybe->server_myds->max_connect_time ) {
		if (thread->curtime >= mybe->server_myds->max_connect_time) {
			if (mirror) {
				PROXY_TRACE();
			}

			string errmsg{};
			const string session_info{ session_fast_forward ? "for 'fast_forward' session " : "" };
			const uint64_t query_time = (thread->curtime - CurrentQuery.start_time) / 1000;

			string_format(
				"Max connect timeout reached while reaching hostgroup %d %safter %llums",
				errmsg, current_hostgroup, session_info.c_str(), query_time
			);

			if (thread) {
				thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
			}
			client_myds->myprot.generate_error_packet(true, true, errmsg.c_str(), PGSQL_ERROR_CODES::ERRCODE_SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION, 
				false, true); 
			RequestEnd(mybe->server_myds);

			string hg_status{};
			generate_status_one_hostgroup(current_hostgroup, hg_status);
			proxy_error("%s . HG status: %s\n", errmsg.c_str(), hg_status.c_str());

			while (previous_status.size()) {
				previous_status.pop();
			}
			if (mybe->server_myds->myconn) {
				// NOTE-3404: Created connection never reached 'connect_cont' phase, due to that internal
				// structures of 'pgsql->net' are not fully initialized.  This induces a leak of the 'fd'
				// associated with the socket opened by the library. To prevent this, we need to call
				// `mysql_real_connect_cont` through `connect_cont`. This way we ensure a proper cleanup of
				// all the resources when 'mysql_close' is later called. For more context see issue #3404.
				mybe->server_myds->myconn->connect_cont(PG_EVENT_NONE);
				mybe->server_myds->destroy_MySQL_Connection_From_Pool(false);
				if (mirror) {
					PROXY_TRACE();
					NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
				}
			}
			mybe->server_myds->max_connect_time = 0;
			NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
		}
	}
	if (mybe->server_myds->myconn == NULL) {
		handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
	}
	if (mybe->server_myds->myconn == NULL) {
		if (mirror) {
			PROXY_TRACE();
			NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
		}
	}

	// NOTE-connect_retries_delay: This check alone is not enough for imposing
	// 'pgsql_thread___connect_retries_delay'. In case of 'async_connect' failing, 'pause_until' should also
	// be set to 'pgsql_thread___connect_retries_delay'. Complementary NOTE below.
	if (mybe->server_myds->myconn == NULL) {
		pause_until = thread->curtime + pgsql_thread___connect_retries_delay * 1000;
		*_rc = 1;
		return false;
	}
	else {
		PgSQL_Data_Stream* myds = mybe->server_myds;
		PgSQL_Connection* myconn = myds->myconn;
		int rc;
		if (default_hostgroup < 0) {
			// we are connected to a Admin module backend
			// we pretend to set a user variable to disable multiplexing
			myconn->set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
		}
		enum session_status st = status;
		if (mybe->server_myds->myconn->async_state_machine == ASYNC_IDLE) {
			st = previous_status.top();
			previous_status.pop();
			NEXT_IMMEDIATE_NEW(st);
		}
		assert(st == status);
		unsigned long long curtime = monotonic_time();

		assert(myconn->async_state_machine != ASYNC_IDLE);
		if (mirror) {
			PROXY_TRACE();
		}
		rc = myconn->async_connect(myds->revents);
		if (myds->mypolls == NULL) {
			// connection yet not in mypolls
			myds->assign_fd_from_pgsql_conn();
			thread->mypolls.add(POLLIN | POLLOUT, myds->fd, myds, curtime);
			if (mirror) {
				PROXY_TRACE();
			}
		} else {
			// See Issue#4919 (https://github.com/sysown/proxysql/issues/4919)
			// File descriptor was already set previously. Let's verify if it has changed
			if (myds->fd != myconn->fd)
			{
				// PQconnectPoll has changed the file descriptor (FD) during the connection process.
				// We need to update the new FD in mypolls, replacing the old one,
				// Note: previous FD is closed by PQconnectPoll
				myds->assign_fd_from_pgsql_conn();
				thread->mypolls.update_fd_at_index(myds->poll_fds_idx, myds->fd);
			}
		}
		switch (rc) {
		case 0:
			myds->myds_type = MYDS_BACKEND;
			myds->DSS = STATE_MARIADB_GENERIC;
			status = WAITING_CLIENT_DATA;
			st = previous_status.top();
			previous_status.pop();
			myds->wait_until = 0;
			if (session_fast_forward) {
				// we have a successful connection and session_fast_forward enabled
				// set DSS=STATE_SLEEP or it will believe it have to use MARIADB client library
				myds->DSS = STATE_SLEEP;
				myds->myconn->send_quit = false;
				myds->myconn->reusable = false;
				// In a 'fast_forward' session after we disable compression for the fronted connection
				// after we have adquired a backend connection, this is, the 'FAST_FORWARD' session status
				// is reached, and the 1-1 connection relationship is established. We can safely do this
				// due two main reasons:
				//   1. The client and backend have to agree on compression, i.e. if the client connected without
				//   compression using fast-forward to a backend connections expected to have compression, it results
				//   in a fallback to a connection without compression, as it's expected by protocol. In this case we do
				//   not require to compress the data received from the backend.
				//   2. The client and backend have agreed in using compression, in this case, the data received from
				//   the backend is already compressed, so we are only required to forward the data to the client.
				// In both cases, we do not require to perform any specials actions for the received data,
				// so we completely disable the compression flag for the client connection.
				client_myds->myconn->set_status(false, STATUS_PGSQL_CONNECTION_COMPRESSION);
			}
			NEXT_IMMEDIATE_NEW(st);
			break;
		case -1:
		case -2:
			PgHGM->p_update_pgsql_error_counter(
				p_pgsql_error_type::pgsql, 
				myconn->parent->myhgc->hid, 
				myconn->parent->address, 
				myconn->parent->port, 9999 /* TODO: fix this mysql_errno(myconn->pgsql)*/);

			if (myds->connect_retries_on_failure > 0) {
				myds->connect_retries_on_failure--;

				if (myconn->is_error_present() && 
					myconn->get_error_code() == PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS) {
					goto __exit_handler_again___status_CONNECTING_SERVER_with_err;
				}
				if (mirror) {
					PROXY_TRACE();
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				// NOTE-connect_retries_delay: In case of failure to connect, if
				// 'pgsql_thread___connect_retries_delay' is set, we impose a delay in the session
				// processing via 'pause_until'. Complementary NOTE above.
				if (pgsql_thread___connect_retries_delay) {
					pause_until = thread->curtime + pgsql_thread___connect_retries_delay * 1000;
					set_status(CONNECTING_SERVER);
					return false;
				}
				NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
			}
			else {
__exit_handler_again___status_CONNECTING_SERVER_with_err:
				bool is_error_present = myconn->is_error_present();
				if (is_error_present) {
					client_myds->myprot.generate_error_packet(true, true, myconn->error_info.message.c_str(), 
						myconn->error_info.code, false, true);
				} else {
					char buf[256];
					sprintf(buf, "Max connect failure while reaching hostgroup %d", current_hostgroup);
					client_myds->myprot.generate_error_packet(true, true, buf, PGSQL_ERROR_CODES::ERRCODE_SQLCLIENT_UNABLE_TO_ESTABLISH_SQLCONNECTION,
						false, true); 
					if (thread) {
						thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
					}
				}
				if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
					// see bug #979
					RequestEnd(myds);
				}
				while (previous_status.size()) {
					st = previous_status.top();
					previous_status.pop();
				}
				if (mirror) {
					PROXY_TRACE();
				}
				myds->destroy_MySQL_Connection_From_Pool(is_error_present);
				myds->max_connect_time = 0;
				NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
			}
			break;
		case 1: // continue on next loop
		default:
			break;
		}
	}
	return false;
}

bool PgSQL_Session::handler_again___status_RESETTING_CONNECTION(int* _rc) {
	assert(mybe->server_myds->myconn);
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	myds->DSS = STATE_MARIADB_QUERY;
	enum session_status st = status;
	if (myds->mypolls == NULL) {
		thread->mypolls.add(POLLIN | POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	
	if (pgsql_thread___connect_timeout_server_max) {
		if (mybe->server_myds->max_connect_time == 0) {
			mybe->server_myds->max_connect_time = thread->curtime + pgsql_thread___connect_timeout_server_max * 1000;
		}
	}
	int rc = myconn->async_reset_session(myds->revents);
	if (rc == 0) {
		__sync_fetch_and_add(&PgHGM->status.backend_reset_connection, 1);
		//myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		myds->myconn->reset();
		myds->DSS = STATE_MARIADB_GENERIC;
		st = previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc == -1) {
			// the command failed
			const bool error_present = myconn->is_error_present();
			PgHGM->p_update_pgsql_error_counter(
				p_pgsql_error_type::pgsql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				(error_present ? 9999 : ER_PROXYSQL_OFFLINE_SRV) // TOFIX: 9999 is a placeholder for the actual error code
			);
			if (error_present == false || (error_present == true && myconn->is_connection_in_reusable_state() == false)) {
				bool retry_conn = false;
				// client error, serious
				detected_broken_connection(__FILE__, __LINE__, __func__, "during Resetting Connection", myconn);
				if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
					retry_conn = true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd = 0;
				if (retry_conn) {
					myds->DSS = STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc = -1;
				return false;
			} else {
				proxy_warning("Error during Resetting Connection: %s\n", myconn->get_error_code_with_message().c_str());
				// we won't go back to PROCESSING_QUERY
				st = previous_status.top();
				previous_status.pop();
				client_myds->myprot.generate_error_packet(true, true, myconn->get_error_message().c_str(), myconn->get_error_code(), false);
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd = 0;
				RequestEnd(myds); //fix bug #682
			}
		} else {
			if (rc == -2) {
				bool retry_conn = false;
				proxy_error("Timeout during Resetting Connection on %s , %d\n", myconn->parent->address, myconn->parent->port);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_CHANGE_USER_TIMEOUT);
				if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
					retry_conn = true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd = 0;
				if (retry_conn) {
					myds->DSS = STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc = -1;
				return false;
			} else {
				// rc==1 , nothing to do for now
			}
		}
	}
	return false;
}

// this function was inline inside PgSQL_Session::get_pkts_from_client
// ClickHouse doesn't support COM_INIT_DB , so we replace it
// with a COM_QUERY running USE
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt) {
	PtrSize_t _new_pkt;
	_new_pkt.ptr = malloc(pkt.size + 4); // USE + space
	memcpy(_new_pkt.ptr, pkt.ptr, 4);
	unsigned char* _c = (unsigned char*)_new_pkt.ptr;
	_c += 4; *_c = 0x03;
	_c += 1; *_c = 'U';
	_c += 1; *_c = 'S';
	_c += 1; *_c = 'E';
	_c += 1; *_c = ' ';
	memcpy((char*)_new_pkt.ptr + 9, (char*)pkt.ptr + 5, pkt.size - 5);
	l_free(pkt.size, pkt.ptr);
	pkt.size += 4;
	pkt.ptr = _new_pkt.ptr;
}

// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it processes the session not MYSQL_SESSION
// Make sure that handler_function() doesn't free the packet
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt) {
	switch (session_type) {
	case PROXYSQL_SESSION_ADMIN:
	case PROXYSQL_SESSION_STATS:
		// this is processed by the admin module
		handler_function(this, (void*)GloAdmin, &pkt);
		l_free(pkt.size, pkt.ptr);
		break;
	case PROXYSQL_SESSION_SQLITE:
		handler_function(this, (void*)GloSQLite3Server, &pkt);
		l_free(pkt.size, pkt.ptr);
		break;
#ifdef PROXYSQLCLICKHOUSE
	case PROXYSQL_SESSION_CLICKHOUSE:
		handler_function(this, (void*)GloClickHouseServer, &pkt);
		l_free(pkt.size, pkt.ptr);
		break;
#endif /* PROXYSQLCLICKHOUSE */
	default:
		// LCOV_EXCL_START
		assert(0);
		// LCOV_EXCL_STOP
	}
}


// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it searches for SQL injection
// it returns true if it detected an SQL injection
bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi() {
	if (client_myds->com_field_list == false) {
		if (qpo->firewall_whitelist_mode != WUS_OFF) {
			struct libinjection_sqli_state state;
			int issqli;
			const char* input = (char*)CurrentQuery.QueryPointer;
			size_t slen = CurrentQuery.QueryLength;
			libinjection_sqli_init(&state, input, slen, FLAG_SQL_MYSQL);
			issqli = libinjection_is_sqli(&state);
			if (issqli) {
				bool allow_sqli = false;
				allow_sqli = GloPgQPro->whitelisted_sqli_fingerprint(state.fingerprint);
				if (allow_sqli) {
					thread->status_variables.stvar[st_var_mysql_whitelisted_sqli_fingerprint]++;
				}
				else {
					thread->status_variables.stvar[st_var_automatic_detected_sqli]++;
					char* username = client_myds->myconn->userinfo->username;
					char* client_address = client_myds->addr.addr;
					proxy_error("SQLinjection detected with fingerprint of '%s' from client %s@%s . Query listed below:\n", state.fingerprint, username, client_address);
					fwrite(CurrentQuery.QueryPointer, CurrentQuery.QueryLength, 1, stderr);
					fprintf(stderr, "\n");
					RequestEnd(NULL);
					return true;
				}
			}
		}
	}
	return false;
}
#if 0
// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP_MULTI_PACKET
//
// replacing the single goto with return true
bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt) {
	if (client_myds->multi_pkt.ptr == NULL) {
		// not initialized yet
		client_myds->multi_pkt.ptr = pkt.ptr;
		client_myds->multi_pkt.size = pkt.size;
	}
	else {
		PtrSize_t tmp_pkt;
		tmp_pkt.ptr = client_myds->multi_pkt.ptr;
		tmp_pkt.size = client_myds->multi_pkt.size;
		client_myds->multi_pkt.size = pkt.size + tmp_pkt.size - sizeof(mysql_hdr);
		client_myds->multi_pkt.ptr = l_alloc(client_myds->multi_pkt.size);
		memcpy(client_myds->multi_pkt.ptr, tmp_pkt.ptr, tmp_pkt.size);
		memcpy((char*)client_myds->multi_pkt.ptr + tmp_pkt.size, (char*)pkt.ptr + sizeof(mysql_hdr), pkt.size - sizeof(mysql_hdr)); // the header is not copied
		l_free(tmp_pkt.size, tmp_pkt.ptr);
		l_free(pkt.size, pkt.ptr);
	}
	if (pkt.size == (0xFFFFFF + sizeof(mysql_hdr))) { // there are more packets
		//goto __get_pkts_from_client;
		return true;
	}
	else {
		// no more packets, move everything back to pkt and proceed
		pkt.ptr = client_myds->multi_pkt.ptr;
		pkt.size = client_myds->multi_pkt.size;
		client_myds->multi_pkt.size = 0;
		client_myds->multi_pkt.ptr = NULL;
		client_myds->DSS = STATE_SLEEP;
	}
	return false;
}


// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command in a large list of possible values
// the most common values for enum_mysql_command are handled from the calling function
// here we only process the not so common ones
// we return false if the enum_mysql_command is not found
bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass) {
	unsigned char c;
	c = *((unsigned char*)pkt->ptr + sizeof(mysql_hdr));
	switch ((enum_mysql_command)c) {
	case _MYSQL_COM_CHANGE_USER:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(pkt, wrong_pass);
		break;
	case _MYSQL_COM_PING:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(pkt);
		break;
	case _MYSQL_COM_SET_OPTION:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(pkt);
		break;
	case _MYSQL_COM_STATISTICS:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(pkt);
		break;
	case _MYSQL_COM_INIT_DB:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(pkt);
		break;
	case _MYSQL_COM_FIELD_LIST:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(pkt);
		break;
	case _MYSQL_COM_PROCESS_KILL:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(pkt);
		break;
	case _MYSQL_COM_RESET_CONNECTION:
		handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(pkt);
		break;
	default:
		return false;
		break;
	}
	return true;
}
#endif

// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = NONE or default
//
// this is triggered when proxysql receives a packet when doesn't expect any
// for example while it is supposed to be sending resultset to client
void PgSQL_Session::handler___status_NONE_or_default(PtrSize_t& pkt) {
	char buf[INET6_ADDRSTRLEN];

	switch (client_myds->client_addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in* ipv4 = (struct sockaddr_in*)client_myds->client_addr;
		inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)client_myds->client_addr;
		inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
		break;
	}
	default:
		sprintf(buf, "localhost");
		break;
	}

	const char cmd = (pkt.ptr && pkt.size > 0) ? *((unsigned char*)pkt.ptr) : '?'; // unknown command
	proxy_error("Unexpected packet '%c' from client %s. Session_status: %d . Disconnecting it\n",
		cmd, buf, status);

	if (pkt.size == 5 && cmd == 'X') {
		if (GloPgSQL_Logger) {
			GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL);
		}
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got QUIT packet\n");
		if (thread) {
			thread->status_variables.stvar[st_var_unexpected_com_quit]++;
		}
	} else {
		if (thread) {
			thread->status_variables.stvar[st_var_unexpected_packet]++;
		}
	}

	l_free(pkt.size, pkt.ptr);
}

// this function was inline inside PgSQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___default() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_UNKNOWN\n");
	if (mirror == false) {
		char buf[INET6_ADDRSTRLEN];
		switch (client_myds->client_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)client_myds->client_addr;
			inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)client_myds->client_addr;
			inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
			break;
		}
		default:
			sprintf(buf, "localhost");
			break;
		}
		// PMC-10001: A unexpected packet has been received from client. This error has two potential causes:
		//  * Bug: ProxySQL state machine wasn't in the correct state when a legitimate client packet was received.
		//  * Client error: The client incorrectly sent a packet breaking PgSQL protocol.
		proxy_error2(10001, "Unexpected packet from client %s . Session_status: %d . Disconnecting it\n", buf, status);
	}
}

int PgSQL_Session::get_pkts_from_client(bool& wrong_pass, PtrSize_t& pkt) {
	int handler_ret = 0;
	unsigned char c;

//__get_pkts_from_client:

	// implement a more complex logic to run even in case of mirror
	// if client_myds , this is a regular client
	// if client_myds == NULL , it is a mirror
	//     process mirror only status==WAITING_CLIENT_DATA
	for (unsigned int j = 0; j < (client_myds->PSarrayIN ? client_myds->PSarrayIN->len : 0) || (mirror == true && status == WAITING_CLIENT_DATA);) {
		
		if (mirror == false) {
			client_myds->PSarrayIN->remove_index(0, &pkt);
		}
		switch (status) {

		case CONNECTING_CLIENT:
			switch (client_myds->DSS) {
			case STATE_SSL_INIT:
			case STATE_SERVER_HANDSHAKE:
				handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
				break;
			default:
				proxy_error("Detected not valid state client state: %d\n", client_myds->DSS);
				handler_ret = -1; //close connection
				return handler_ret;
				break;
			}
			break;

		case WAITING_CLIENT_DATA:
/*			// this is handled only for real traffic, not mirror
			if (pkt.size == (0xFFFFFF + sizeof(mysql_hdr))) {
				// we are handling a multi-packet
				switch (client_myds->DSS) { // real traffic only
				case STATE_SLEEP:
					client_myds->DSS = STATE_SLEEP_MULTI_PACKET;
					break;
				case STATE_SLEEP_MULTI_PACKET:
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
				}
			}
*/
			switch (client_myds->DSS) {
/*			case STATE_SLEEP_MULTI_PACKET:
				if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(pkt)) {
					// if handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET
					// returns true it meansa we need to reiterate
					goto __get_pkts_from_client;
				}
				// Note: the above function can change DSS to STATE_SLEEP
				// in that case we don't break from the witch but continue
				if (client_myds->DSS != STATE_SLEEP) // if DSS==STATE_SLEEP , we continue
					break;
*/
			case STATE_SLEEP:	// only this section can be executed ALSO by mirror
				command_counters->incr(thread->curtime / 1000000);
				if (transaction_persistent_hostgroup == -1) {
					if (pgsql_thread___set_query_lock_on_hostgroup == 0) { // behavior before 2.0.6
						current_hostgroup = default_hostgroup;
					} else {
						if (locked_on_hostgroup == -1) {
							current_hostgroup = default_hostgroup;
						} else {
							current_hostgroup = locked_on_hostgroup;
						}
					}
				}
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , client_myds=%p . Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n", this, client_myds);
				if (session_fast_forward) { // if it is fast forward
					// If this is a 'fast_forward' session that hasn't yet received a backend connection, we don't
					// forward 'QUIT' packets, since this will make the act of obtaining a connection pointless.
					// Instead, we intercept the 'QUIT' packet and end the 'PgSQL_Session'.
					unsigned char command = *(static_cast<unsigned char*>(pkt.ptr));
					if (command == 'X') {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got QUIT packet\n");
						if (GloPgSQL_Logger) { GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
						l_free(pkt.size, pkt.ptr);
						handler_ret = -1;
						return handler_ret;
					}

					mybe = find_or_create_backend(current_hostgroup); // set a backend
					mybe->server_myds->reinit_queues();             // reinitialize the queues in the myds . By default, they are not active
					mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size); // move the first packet
					previous_status.push(FAST_FORWARD); // next status will be FAST_FORWARD . Now we need a connection

					// If this is a 'fast_forward' session, we impose the 'connect_timeout' prior to actually getting the
					// connection from the 'connection_pool'. This is used to ensure that we kill the session if
					// 'CONNECTING_SERVER' isn't completed before this timeout expiring. For example, if 'max_connections'
					// is reached for the target hostgroup.
					if (mybe->server_myds->max_connect_time == 0) {
						uint64_t connect_timeout =
							pgsql_thread___connect_timeout_server < pgsql_thread___connect_timeout_server_max ?
							pgsql_thread___connect_timeout_server_max : pgsql_thread___connect_timeout_server;
						mybe->server_myds->max_connect_time = thread->curtime + connect_timeout * 1000;
					}
					// Impose the same connection retrying policy as done for regular connections during
					// 'MYSQL_CON_QUERY'.
					mybe->server_myds->connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
					// 'CurrentQuery' isn't used for 'FAST_FORWARD' but we update it for using it as a session
					// startup time for when a fast_forward session has attempted to obtain a connection.
					CurrentQuery.start_time = thread->curtime;

					{
						//NEXT_IMMEDIATE(CONNECTING_SERVER);  // we create a connection . next status will be FAST_FORWARD
						// we can't use NEXT_IMMEDIATE() inside get_pkts_from_client()
						// instead we set status to CONNECTING_SERVER and return 0
						// when we exit from get_pkts_from_client() we expect the label "handler_again"
						set_status(CONNECTING_SERVER);
						return 0;
					}
				}
				c = *((unsigned char*)pkt.ptr);
				if (client_myds != NULL) {
					if (session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) {
						c = *((unsigned char*)pkt.ptr);
						if (c == 'Q') {
							handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(pkt);
						} else if (c == 'X') {
							//proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
							//if (GloPgSQL_Logger) { GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
							l_free(pkt.size, pkt.ptr);
							handler_ret = -1;
							return handler_ret;
						} else if (c == 'P' || c == 'B' || c == 'C' || c == 'D' || c == 'E') {
							l_free(pkt.size, pkt.ptr);
							continue;
						} else {
							proxy_error("Not implemented yet. Message type:'%c'\n", c);
							client_myds->setDSS_STATE_QUERY_SENT_NET();
							client_myds->myprot.generate_error_packet(true, true, "Feature not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
								false, true);
							l_free(pkt.size, pkt.ptr);
							client_myds->DSS = STATE_SLEEP;
							//handler_ret = -1;
							return handler_ret;
						}
					} else {
						char command = c = *((unsigned char*)pkt.ptr);
						switch (command) {
						case 'Q':
						{
							__sync_add_and_fetch(&thread->status_variables.stvar[st_var_queries], 1);
							if (session_type == PROXYSQL_SESSION_PGSQL) {
								bool rc_break = false;
								bool lock_hostgroup = false;
								if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
									// Note: CurrentQuery sees the query as sent by the client.
									// shortly after, the packets it used to contain the query will be deallocated
									CurrentQuery.begin((unsigned char*)pkt.ptr, pkt.size, true);
								}
								rc_break = handler_special_queries(&pkt,&lock_hostgroup);
								if (rc_break == true) {
									if (mirror == false) {
										// track also special queries
										//RequestEnd(NULL);
										// we moved this inside handler_special_queries()
										// because a pointer was becoming invalid
										break;
									}
									else {
										handler_ret = -1;
										return handler_ret;
									}
								}
								timespec begint;
								timespec endt;
								if (thread->variables.stats_time_query_processor) {
									clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begint);
								}
								unsigned int query_len = pkt.size - 5; // excluding header
								char* query_ptr = (char*)pkt.ptr + 5;

								qpo = GloPgQPro->process_query(this, query_ptr, query_len, &CurrentQuery);
								if (thread->variables.stats_time_query_processor) {
									clock_gettime(CLOCK_THREAD_CPUTIME_ID, &endt);
									thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
										(endt.tv_sec * 1000000000 + endt.tv_nsec) -
										(begint.tv_sec * 1000000000 + begint.tv_nsec);
								}
								assert(qpo);	// GloPgQPro->process_mysql_query() should always return a qpo
								// ===================================================
								if (qpo->max_lag_ms >= 0) {
									thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
								}
								rc_break = handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(&pkt, &lock_hostgroup);
								if (mirror == false && rc_break == false) {
									if (pgsql_thread___automatic_detect_sqli) {
										if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi()) {
											handler_ret = -1;
											return handler_ret;
										}
									}
								}
								if (rc_break == true) {
									if (mirror == false) {
										break;
									}
									else {
										handler_ret = -1;
										return handler_ret;
									}
								}
								if (mirror == false) {
									handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
								}

								if (pgsql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
									if (locked_on_hostgroup < 0) {
										if (lock_hostgroup) {
											// we are locking on hostgroup now
											if (qpo->destination_hostgroup >= 0) {
												if (transaction_persistent_hostgroup == -1) {
													current_hostgroup = qpo->destination_hostgroup;
												}
											}
											locked_on_hostgroup = current_hostgroup;
											thread->status_variables.stvar[st_var_hostgroup_locked]++;
											thread->status_variables.stvar[st_var_hostgroup_locked_set_cmds]++;
										}
									}
									if (locked_on_hostgroup >= 0) {
										if (current_hostgroup != locked_on_hostgroup) {
											client_myds->DSS = STATE_QUERY_SENT_NET;
											int l = CurrentQuery.QueryLength;
											char* end = (char*)"";
											if (l > 256) {
												l = 253;
												end = (char*)"...";
											}
											string nqn = string((char*)CurrentQuery.QueryPointer, l);
											char* err_msg = (char*)"Session trying to reach HG %d while locked on HG %d . Rejecting query: %s";
											char* buf = (char*)malloc(strlen(err_msg) + strlen(nqn.c_str()) + strlen(end) + 64);
											sprintf(buf, err_msg, current_hostgroup, locked_on_hostgroup, nqn.c_str(), end);
											client_myds->myprot.generate_error_packet(true, true, buf, PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION,
												false, true);
											thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
											RequestEnd(NULL);
											free(buf);
											l_free(pkt.size, pkt.ptr);
											break;
										}
									}
								}
								mybe = find_or_create_backend(current_hostgroup);
								status = PROCESSING_QUERY;
								// set query retries
								mybe->server_myds->query_retries_on_failure = pgsql_thread___query_retries_on_failure;
								// if a number of retries is set in mysql_query_rules, that takes priority
								if (qpo) {
									if (qpo->retries >= 0) {
										mybe->server_myds->query_retries_on_failure = qpo->retries;
									}
								}
								mybe->server_myds->connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
								mybe->server_myds->wait_until = 0;
								pause_until = 0;
								if (pgsql_thread___default_query_delay) {
									pause_until = thread->curtime + pgsql_thread___default_query_delay * 1000;
								}
								if (qpo) {
									if (qpo->delay > 0) {
										if (pause_until == 0)
											pause_until = thread->curtime;
										pause_until += qpo->delay * 1000;
									}
								}

								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Received query to be processed...\n");
								mybe->server_myds->killed_at = 0;
								mybe->server_myds->kill_type = 0;
								mybe->server_myds->pgsql_real_query.init(&pkt);
								mybe->server_myds->statuses.questions++;
								client_myds->setDSS_STATE_QUERY_SENT_NET();
							}
						}
						break;
						case 'X':
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got QUIT packet\n");
							if (GloPgSQL_Logger) { GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
							l_free(pkt.size, pkt.ptr);
							handler_ret = -1;
							return handler_ret;
							break;
						// Extended Query Handling
						case 'P':
							if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_PARSE(pkt) == false) {
								handler_ret = -1;
								return handler_ret;
							}
							break;
						case 'D':
							if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_DESCRIBE(pkt) == false) {
								handler_ret = -1;
								return handler_ret;
							}
							break;
						case 'C':
							if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_CLOSE(pkt) == false) {
								handler_ret = -1;
								return handler_ret;
							}
							break;
						case 'B':
							if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_BIND(pkt) == false) {
								handler_ret = -1;
								return handler_ret;
							}
							break;
						case 'E':
							if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_EXECUTE(pkt) == false) {
								handler_ret = -1;
								return handler_ret;
							}
							break;
						case 'S':
						{
#ifdef DEBUG
							dbg_extended_query_backend_conn = nullptr;
#endif
							// we do not need sync packet anymore
							l_free(pkt.size, pkt.ptr);
							pkt = { 0, nullptr };
							bind_waiting_for_execute.reset(nullptr);

						__run_sync_again:
							int rc = handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_SYNC();

							if (rc == -1) {
								handler_ret = -1;
								return handler_ret;
							}

							// if the previous message succeeded (it was not queried on backend server)
							// and there are more messages in the queue, sync needs to be executed again
							if (rc == 0 && extended_query_frame.empty() == false) {
								writeout();
								goto __run_sync_again;
							}
						}
							break;
						default:
							proxy_error("Not implemented yet. Message type:'%c'\n", c);
							client_myds->setDSS_STATE_QUERY_SENT_NET();
							client_myds->myprot.generate_error_packet(true, true, "Feature not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
								false, true);
							l_free(pkt.size, pkt.ptr);
							client_myds->DSS = STATE_SLEEP;
							return handler_ret;
						}
					}
					break;
				}
				break;
			default:
				handler___status_WAITING_CLIENT_DATA___default();
				handler_ret = -1;
				return handler_ret;
				break;
			}
			break;
		case FAST_FORWARD:
			mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			break;
			// This state is required because it covers the following situation:
			//  1. A new connection is created by a client and the 'FAST_FORWARD' mode is enabled.
			//  2. The first packet received for this connection isn't a whole packet, i.e, it's either
			//     split into multiple packets, or it doesn't fit 'queueIN' size (typically
			//     QUEUE_T_DEFAULT_SIZE).
			//  3. Session is still in 'CONNECTING_SERVER' state, BUT further packets remain to be received
			//     from the initial split packet.
			//
			//  Because of this, packets received during 'CONNECTING_SERVER' when the previous state is
			//  'FAST_FORWARD' should be pushed to 'PSarrayOUT'.
		case CONNECTING_SERVER:
			if (previous_status.empty() == false && previous_status.top() == FAST_FORWARD) {
				mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				break;
			}
		case session_status___NONE:
		default:
			handler___status_NONE_or_default(pkt);
			handler_ret = -1;
			return handler_ret;
			break;
		}
	}
	return handler_ret;
}
// end of PgSQL_Session::get_pkts_from_client()


// this function returns:
// 0 : no action
// -1 : the calling function will return
// 1 : call to NEXT_IMMEDIATE
int PgSQL_Session::handler_ProcessingQueryError_CheckBackendConnectionStatus(PgSQL_Data_Stream* myds) {
	PgSQL_Connection* myconn = myds->myconn;
	// the query failed
	if (myconn->IsServerOffline()) {
		// Set maximum connect time if connect timeout is configured
		if (pgsql_thread___connect_timeout_server_max) {
			myds->max_connect_time = thread->curtime + pgsql_thread___connect_timeout_server_max * 1000;
		}

		// Variables to track retry and error conditions
		bool retry_conn = false;
		if (myconn->server_status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
			thread->status_variables.stvar[st_var_backend_lagging_during_query]++;
			proxy_error("Detected a lagging server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
			PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_LAGGING_SRV);
		} else {
			thread->status_variables.stvar[st_var_backend_offline_during_query]++;
			proxy_error("Detected an offline server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
			PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_OFFLINE_SRV);
		}

		// Retry the query if retries are allowed and conditions permit
		if (myds->query_retries_on_failure > 0) {
			myds->query_retries_on_failure--;
			if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
				if (myds->myconn->query_result && myds->myconn->query_result->is_transfer_started()) {
					// transfer to frontend has started, we cannot retry
				} else {
					retry_conn = true;
					proxy_warning("Retrying query.\n");
				}
			}
		}
		myds->destroy_MySQL_Connection_From_Pool(false);
		myds->fd = 0;
		if (retry_conn) {
			myds->DSS = STATE_NOT_INITIALIZED;
			// Sets the previous status of the PgSQL session according to the current status.
			set_previous_status_mode3();
			return 1;
		}
		return -1;
	}
	return 0;
}

void PgSQL_Session::SetQueryTimeout() {
	mybe->server_myds->wait_until = 0;
	if (qpo) {
		if (qpo->timeout > 0) {
			unsigned long long qr_timeout = qpo->timeout;
			mybe->server_myds->wait_until = thread->curtime;
			mybe->server_myds->wait_until += qr_timeout * 1000;
		}
	}
	if (pgsql_thread___default_query_timeout) {
		if (mybe->server_myds->wait_until == 0) {
			mybe->server_myds->wait_until = thread->curtime;
			unsigned long long def_query_timeout = pgsql_thread___default_query_timeout;
			mybe->server_myds->wait_until += def_query_timeout * 1000;
		}
	}
}

// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(CONNECTING_SERVER) needs to be called
// false: continue
bool PgSQL_Session::handler_minus1_ClientLibraryError(PgSQL_Data_Stream* myds) {
	PgSQL_Connection* myconn = myds->myconn;
	bool retry_conn = false;
	// client error, serious
	detected_broken_connection(__FILE__, __LINE__, __func__, "running query", myconn, true);
	if (myds->query_retries_on_failure > 0) {
		myds->query_retries_on_failure--;
		if ((myconn->reusable == true) && myconn->IsActiveTransaction() == false && myconn->MultiplexDisabled() == false) {
			if (myconn->query_result && myconn->query_result->is_transfer_started()) {
				// transfer to frontend has started, we cannot retry
			} else {
				// This should never occur.
				if (myconn->processing_multi_statement == true) {
					// we are in the process of retriving results from a multi-statement query
					proxy_warning("Disabling query retry because we were in middle of processing results\n");
				} else {
					retry_conn = true;
					proxy_warning("Retrying query.\n");
				}
			}
		}
	}
	myds->destroy_MySQL_Connection_From_Pool(false);
	myds->fd = 0;
	if (retry_conn) {
		myds->DSS = STATE_NOT_INITIALIZED;
		// Sets the previous status of the PgSQL session according to the current status.
		set_previous_status_mode3();
		return true;
	}
	return false;
}


// this function was inline
void PgSQL_Session::handler_minus1_LogErrorDuringQuery(PgSQL_Connection* myconn) {
	if (pgsql_thread___verbose_query_error) {
		proxy_warning("Error during query on (%d,%s,%d,%d) , user \"%s@%s\" , dbname \"%s\" , %s . digest_text = \"%s\"\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_backend_pid(), client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char*)"unknown"), client_myds->myconn->userinfo->dbname, myconn->get_error_code_with_message().c_str(), CurrentQuery.QueryParserArgs.digest_text);
	} else {
		proxy_warning("Error during query on (%d,%s,%d,%d): %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_backend_pid(), myconn->get_error_code_with_message().c_str());
	}
	PgHGM->add_pgsql_errors(myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, client_myds->myconn->userinfo->username, 
		(client_myds->addr.addr ? client_myds->addr.addr : "unknown"), client_myds->myconn->userinfo->dbname, 
		myconn->get_error_code_str(), myconn->get_error_message().c_str());
}


// this function used to be inline.
// now it returns:
// true:
//		if handler_ret == -1 : return
//		if handler_ret == 0 : NEXT_IMMEDIATE(CONNECTING_SERVER) needs to be called
// false: continue
bool PgSQL_Session::handler_minus1_HandleErrorCodes(PgSQL_Data_Stream* myds, int& handler_ret) {
	bool retry_conn = false;
	PgSQL_Connection* myconn = myds->myconn;
	handler_ret = 0; // default
	switch (myconn->get_error_code()) {
	case PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED:  // Query execution was interrupted
		if (killed == true) { // this session is being kiled
			handler_ret = -1;
			return true;
		}
		if (myds->killed_at) {
			// we intentionally killed the query
			break;
		}
		break;
	case PGSQL_ERROR_CODES::ERRCODE_ADMIN_SHUTDOWN: // Server shutdown in progress. Requested by Admin
	case PGSQL_ERROR_CODES::ERRCODE_CRASH_SHUTDOWN: // Server shutdown in progress
	case PGSQL_ERROR_CODES::ERRCODE_CANNOT_CONNECT_NOW: // Server in initialization mode and not ready to handle new connections
		myconn->parent->connect_error(9999);
		if (myds->query_retries_on_failure > 0) {
			myds->query_retries_on_failure--;
			if ((myconn->reusable == true) && myconn->IsActiveTransaction() == false && myconn->MultiplexDisabled() == false) {
				retry_conn = true;
				proxy_warning("Retrying query.\n");
			}
		}
		myds->destroy_MySQL_Connection_From_Pool(false);
		myconn = myds->myconn;
		myds->fd = 0;
		if (retry_conn) {
			myds->DSS = STATE_NOT_INITIALIZED;
			//previous_status.push(PROCESSING_QUERY);
			set_previous_status_mode3(false);
			return true; // it will call NEXT_IMMEDIATE(CONNECTING_SERVER);
			//NEXT_IMMEDIATE(CONNECTING_SERVER);
		}
		//handler_ret = -1;
		//return handler_ret;
		break;
	case PGSQL_ERROR_CODES::ERRCODE_OUT_OF_MEMORY:
		proxy_warning("Error OUT_OF_MEMORY during query on (%d,%s,%d,%d): %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_backend_pid(), myconn->get_error_code_with_message().c_str());
		break;
	default:
		break; // continue normally
	}
	return false;
}

// this function used to be inline.
void PgSQL_Session::handler_minus1_GenerateErrorMessage(PgSQL_Data_Stream* myds, bool& wrong_pass) {
	PgSQL_Connection* myconn = myds->myconn;

	if (myconn == NULL) {
		client_myds->myprot.generate_error_packet(true, true, "Lost connection to PostgreSQL server during query",
			PGSQL_ERROR_CODES::ERRCODE_CONNECTION_FAILURE, false);
		return;
	}

	switch (status) {
	case PROCESSING_STMT_EXECUTE:
	case PROCESSING_QUERY:
		PgSQL_Result_to_PgSQL_wire(myconn, myds);
		break;
	case PROCESSING_STMT_DESCRIBE:
	case PROCESSING_STMT_PREPARE:
		client_myds->myprot.generate_error_packet(true, true, myconn->get_error_message().c_str(), myconn->get_error_code(), false);
		if (previous_status.size()) {
			// an STMT_PREPARE failed
			// we have a previous status, probably STMT_EXECUTE,
			//    but returning to that status is not safe after STMT_PREPARE failed
			// for this reason we exit immediately
			wrong_pass = true;
		}
		break;
	default:
		// LCOV_EXCL_START
		assert(0);
		break;
		// LCOV_EXCL_STOP
	}
}

// this function was inline
void PgSQL_Session::handler_minus1_HandleBackendConnection(PgSQL_Data_Stream* myds) {
	PgSQL_Connection* myconn = myds->myconn;
	if (myconn) {
		myconn->reduce_auto_increment_delay_token();
		if (pgsql_thread___multiplexing && (myconn->reusable == true) && myconn->IsActiveTransaction() == false && myconn->MultiplexDisabled() == false) {
			myds->DSS = STATE_NOT_INITIALIZED;
			myds->return_MySQL_Connection_To_Pool();
		} else {
			myconn->async_state_machine = ASYNC_IDLE;
			myds->DSS = STATE_MARIADB_GENERIC;
		}
	}
}

// this function was inline
int PgSQL_Session::RunQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn) {
	PROXY_TRACE2();
	int rc = 0;
	switch (status) {
	case PROCESSING_QUERY:
		rc = myconn->async_query(myds->revents, myds->pgsql_real_query.QueryPtr, myds->pgsql_real_query.QuerySize);
		break;
	case PROCESSING_STMT_PREPARE:
		{
			if (CurrentQuery.extended_query_info.stmt_backend_id == 0) {
				uint32_t backend_stmt_id = myconn->local_stmts->generate_new_backend_stmt_id();
				CurrentQuery.extended_query_info.stmt_backend_id = backend_stmt_id;
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Session %p myconn %p pgsql_conn %p Processing STMT_PREPARE with new backend_stmt_id=%u\n", 
					this, myconn, myconn->pgsql_conn, backend_stmt_id);
			}
			 // this is used to generate the name of the prepared statement in the backend
			const std::string& backend_stmt_name = std::string(PROXYSQL_PS_PREFIX) + std::to_string(CurrentQuery.extended_query_info.stmt_backend_id);
			rc = myconn->async_query(myds->revents, (char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength, 
				backend_stmt_name.c_str(), PGSQL_EXTENDED_QUERY_TYPE_PARSE, &CurrentQuery.extended_query_info);
		}	
		break;
	case PROCESSING_STMT_DESCRIBE:
	case PROCESSING_STMT_EXECUTE:
		assert(CurrentQuery.extended_query_info.stmt_backend_id);
		{
			PgSQL_Extended_Query_Type type = 
				(status == PROCESSING_STMT_DESCRIBE) ? PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE : PGSQL_EXTENDED_QUERY_TYPE_EXECUTE;
			const std::string& backend_stmt_name = 
				std::string(PROXYSQL_PS_PREFIX) + std::to_string(CurrentQuery.extended_query_info.stmt_backend_id);
			rc = myconn->async_query(myds->revents, nullptr, 0, backend_stmt_name.c_str(), type, &CurrentQuery.extended_query_info);

			// Handle edge case: Since libpq automatically sends a Sync after Execute,
			// the Bind message is no longer pending on the backend. We must reset
			// bind_waiting_for_execute in case the client sends a sequence like
			// Bind/Describe/Execute/Describe/Sync, so that a subsequent Describe Portal
			// does not incorrectly assume a pending Bind.
			if (rc == 0 && type == PGSQL_EXTENDED_QUERY_TYPE_EXECUTE) {
				bind_waiting_for_execute.reset(nullptr);
			}
		}
		break;
/*	case PROCESSING_STMT_EXECUTE:
		assert(CurrentQuery.stmt_backend_id);
		{
			const std::string& backend_stmt_name = std::string(PROXYSQL_PS_PREFIX) + std::to_string(CurrentQuery.stmt_backend_id);
			const PgSQL_Extended_Query_Info extended_query_info = {
				backend_stmt_name.c_str(), // Name of the prepared statement in the backend
				CurrentQuery.stmt_portal_name, // Name of the portal on the backend
				CurrentQuery.bind_msg,
				PGSQL_EXTENDED_QUERY_TYPE_EXECUTE, // Type of extended query message
				CurrentQuery.stmt_msg_type
			};
			rc = myconn->async_query(myds->revents, (char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength, &extended_query_info);
		}
		break;
*/
	default:
		// LCOV_EXCL_START
		assert(0);
		break;
		// LCOV_EXCL_STOP
	}
	return rc;
}

// this function was inline
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA() {
	// NOTE: Maintenance of 'multiplex_delayed' has been moved to 'housekeeping_before_pkts'. The previous impl
	// is left below as an example of how to perform a more passive maintenance over session connections.
}

int PgSQL_Session::handler() {
#if ENABLE_TIMER
	Timer timer(thread->Timers.Sessions_Handlers);
#endif // ENABLE_TIMER
	int handler_ret = 0;
	bool wrong_pass = false;
	if (to_process == 0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET, 1, "Thread=%p, Session=%p -- Processing session %p\n", this->thread, this, this);
	//unsigned int j;
	//unsigned char c;

//	FIXME: Sessions without frontend are an ugly hack
	if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
		if (client_myds == NULL) {
			// if we are here, probably we are trying to ping backends
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Processing session %p without client_myds\n", this);
			assert(mybe);
			assert(mybe->server_myds);
			goto handler_again;
		}
		else {
			if (mirror == true) {
				if (mirrorPkt.ptr) { // this is the first time we call handler()
					pkt.ptr = mirrorPkt.ptr;
					pkt.size = mirrorPkt.size;
					mirrorPkt.ptr = NULL; // this will prevent the copy to happen again
				}
				else {
					if (status == WAITING_CLIENT_DATA) {
						// we are being called a second time with WAITING_CLIENT_DATA
						handler_ret = 0;
						return handler_ret;
					}
				}
			}
		}
	}
	if (!hgs_expired_conns.empty())
		housekeeping_before_pkts();

	handler_ret = get_pkts_from_client(wrong_pass, pkt);
	if (handler_ret != 0) {
		return handler_ret;
	}

handler_again:

	switch (status) {
		// FIXME: move it to bottom
	case PROCESSING_EXTENDED_QUERY_SYNC:
	{
		int rc = handler___status_PROCESSING_EXTENDED_QUERY_SYNC();
		if (rc == -1) { 
			handler_ret = -1;
			return handler_ret;
		}

		// Extended query synchronization complete; clean up and prepare for next command
		if (rc == 0){
			if (extended_query_frame.empty() == false) {
				writeout();
				NEXT_IMMEDIATE(PROCESSING_EXTENDED_QUERY_SYNC);
			}

			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Extended query sync completed for session %p\n", this);
			// we are done with extended query sync
			bind_waiting_for_execute.reset(nullptr);

			if (PgSQL_Backend* _mybe = find_backend(current_hostgroup)) {
				if (PgSQL_Data_Stream* myds = _mybe->server_myds) {
					if (myds->myconn) {
#ifdef DEBUG
						assert(dbg_extended_query_backend_conn == myds->myconn);
#endif
						// Return to pool if connection is reusable
						finishQuery(myds, myds->myconn, false);
					}
				}
			}
		}
		goto handler_again;
	}
		break;
	case WAITING_CLIENT_DATA:
		// housekeeping
		handler___status_WAITING_CLIENT_DATA();
		break;
	case FAST_FORWARD:
	{
		if (mybe->server_myds->mypolls == NULL) {
			// register the PgSQL_Data_Stream
			thread->mypolls.add(POLLIN | POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
		}
		client_myds->PSarrayOUT->copy_add(mybe->server_myds->PSarrayIN, 0, mybe->server_myds->PSarrayIN->len);

		constexpr unsigned char ready_packet[] = { 0x5A, 0x00, 0x00, 0x00, 0x05 };
		bool is_copy_ready_packet = false;
		while (mybe->server_myds->PSarrayIN->len) {

			// if session_fast_forward type is COPY STDIN, we need to check if it is ready packet
			if (session_fast_forward == SESSION_FORWARD_TYPE_COPY_FROM_STDIN_STDOUT) {
				const PtrSize_t& data = mybe->server_myds->PSarrayIN->pdata[mybe->server_myds->PSarrayIN->len - 1];
				if (is_copy_ready_packet == false && data.size == 6) {
					//const unsigned char* ptr = (static_cast<unsigned char*>(data.ptr) /*+ (data.size - 6)*/);
					if (memcmp(data.ptr, ready_packet, sizeof(ready_packet)) == 0) {
						is_copy_ready_packet = true;
					}
				}
			}
			mybe->server_myds->PSarrayIN->remove_index(mybe->server_myds->PSarrayIN->len - 1, NULL);
		}

		// if ready packet is found, we need to switch back to normal mode
		if (is_copy_ready_packet) {
			switch_fast_forward_to_normal_mode();
		}
	}
		break;
	case CONNECTING_CLIENT:
		//fprintf(stderr,"CONNECTING_CLIENT\n");
		// FIXME: to implement
		break;
	case PINGING_SERVER:
	{
		int rc = handler_again___status_PINGING_SERVER();
		if (rc == -1) { // if the ping fails, we destroy the session
			handler_ret = -1;
			return handler_ret;
		}
	}
	break;

	case RESETTING_CONNECTION:
	{
		int rc = handler_again___status_RESETTING_CONNECTION();
		if (rc == -1) { // we always destroy the session
			handler_ret = -1;
			return handler_ret;
		}
	}
	break;

	case PROCESSING_STMT_PREPARE:
	case PROCESSING_STMT_EXECUTE:
	case PROCESSING_STMT_DESCRIBE:
	case PROCESSING_QUERY:
		//fprintf(stderr,"PROCESSING_QUERY\n");
		if (pause_until > thread->curtime) {
			handler_ret = 0;
			return handler_ret;
		}
		if (pgsql_thread___connect_timeout_server_max) {
			if (mybe->server_myds->max_connect_time == 0)
				mybe->server_myds->max_connect_time = thread->curtime + (long long)pgsql_thread___connect_timeout_server_max * 1000;
		}
		else {
			mybe->server_myds->max_connect_time = 0;
		}
		if (
			(mybe->server_myds->myconn && mybe->server_myds->myconn->async_state_machine != ASYNC_IDLE && mybe->server_myds->wait_until && thread->curtime >= mybe->server_myds->wait_until)
			// query timed out
			||
			(killed == true) // session was killed by admin
			) {
			// we only log in case on timing out here. Logging for 'killed' is done in the places that hold that contextual information.
			if (mybe->server_myds->myconn && (mybe->server_myds->myconn->async_state_machine != ASYNC_IDLE) && mybe->server_myds->wait_until && (thread->curtime >= mybe->server_myds->wait_until)) {
				std::string query{};

				if (CurrentQuery.extended_query_info.stmt_info == NULL) { // text protocol
					query = std::string{ mybe->server_myds->myconn->query.ptr, mybe->server_myds->myconn->query.length };
				} else { // prepared statement
					query = std::string{ CurrentQuery.extended_query_info.stmt_info->query, CurrentQuery.extended_query_info.stmt_info->query_length };
				}

				std::string client_addr{ "" };
				int client_port = 0;

				if (client_myds) {
					client_addr = client_myds->addr.addr ? client_myds->addr.addr : "";
					client_port = client_myds->addr.port;
				}
				
				proxy_warning(
					"Terminating running query %s on connection %s:%d from client %s:%d because it timed out.\n",
					query.c_str(),
					mybe->server_myds->myconn->parent->address,
					mybe->server_myds->myconn->parent->port,
					client_addr.c_str(),
					client_port
				);
			}
			// it calls handler_again___new_thread_to_cancel_query() to initiate the killing of the connection
			// associated with the session that timed out.
			handler_again___new_thread_to_cancel_query();
		}
		if (mybe->server_myds->DSS == STATE_NOT_INITIALIZED) {
			// we don't have a backend yet
			// It saves the current processing status of the session (status) onto the previous_status stack
			// Sets the previous status of the PgSQL session according to the current status.
			set_previous_status_mode3();
			// It transitions the session to the CONNECTING_SERVER state immediately.
			NEXT_IMMEDIATE(CONNECTING_SERVER);
		} else {
			PgSQL_Data_Stream* myds = mybe->server_myds;
			PgSQL_Connection* myconn = myds->myconn;
			bool processing_extended_query = (status == PROCESSING_STMT_PREPARE || 
											  status == PROCESSING_STMT_EXECUTE || 
											  status == PROCESSING_STMT_DESCRIBE);
			mybe->server_myds->max_connect_time = 0;
			// we insert it in mypolls only if not already there
			if (myds->mypolls == NULL) {
				thread->mypolls.add(POLLIN | POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
			}
			if (default_hostgroup >= 0) {
				if (handler_again___verify_backend_user_db()) {
					goto handler_again;
				}
				if (mirror == false) { // do not care about autocommit and charset if mirror
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , default_HG=%d server_myds DSS=%d , locked_on_HG=%d\n", this, default_hostgroup, mybe->server_myds->DSS, locked_on_hostgroup);
					if (mybe->server_myds->DSS == STATE_READY || mybe->server_myds->DSS == STATE_MARIADB_GENERIC) {
						if (handler_again___verify_init_connect()) {
							goto handler_again;
						}
						if (locked_on_hostgroup == -1 || locked_on_hostgroup_and_all_variables_set == false) {

							for (auto i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
								auto client_hash = client_myds->myconn->var_hash[i];
#ifdef DEBUG
								if (GloVars.global.gdbg) {
									proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session %p , variable %s has value %s\n", this, pgsql_tracked_variables[i].set_variable_name, client_myds->myconn->variables[i].value);
								}
#endif // DEBUG
								if (client_hash) {
									auto server_hash = myconn->var_hash[i];
									if (client_hash != server_hash) {
										if (!myconn->var_absent[i] && pgsql_variables.verify_variable(this, i)) {
											goto handler_again;
										}
									}
								}
							}
							PgSQL_Connection* c_con = client_myds->myconn;
							vector<uint32_t>::const_iterator it_c = c_con->dynamic_variables_idx.begin();  // client connection iterator
							for (; it_c != c_con->dynamic_variables_idx.end(); it_c++) {
								auto i = *it_c;
								auto client_hash = c_con->var_hash[i];
								auto server_hash = myconn->var_hash[i];
								if (client_hash != server_hash) {
									if (!myconn->var_absent[i] && pgsql_variables.verify_variable(this, i)) {
										goto handler_again;
									}
								}
							}

							if (locked_on_hostgroup != -1) {
								locked_on_hostgroup_and_all_variables_set = true;
							}
						}
					}
					if (status == PROCESSING_STMT_DESCRIBE || status == PROCESSING_STMT_EXECUTE) {
						uint32_t backend_stmt_id = myconn->local_stmts->find_backend_stmt_id_from_global_id(CurrentQuery.extended_query_info.stmt_global_id);
						if (backend_stmt_id == 0) {
							// the connection doesn't have the prepared statements prepared
							// we try to create it now
							if (CurrentQuery.extended_query_info.stmt_info == NULL) {
								// this should never happen
								proxy_error("Session %p, status %d, CurrentQuery.stmt_info is NULL\n", this, status);
								assert(0);
							}
							if (status == PROCESSING_STMT_DESCRIBE) {
								CurrentQuery.QueryLength = CurrentQuery.extended_query_info.stmt_info->query_length;
								CurrentQuery.QueryPointer = (unsigned char*)CurrentQuery.extended_query_info.stmt_info->query;
								// NOTE: Update 'first_comment' with the 'first_comment' from the retrieved
								// 'stmt_info' from the found prepared statement. 'CurrentQuery' requires its
								// own copy of 'first_comment' because it will later be free by 'QueryInfo::end'.
								if (CurrentQuery.extended_query_info.stmt_info->first_comment) {
									CurrentQuery.QueryParserArgs.first_comment = strdup(CurrentQuery.extended_query_info.stmt_info->first_comment);
								}
							}
							if (CurrentQuery.extended_query_info.stmt_info->parse_param_types.empty() == false) {
								CurrentQuery.extended_query_info.parse_param_types = CurrentQuery.extended_query_info.stmt_info->parse_param_types;
							}
							if (CurrentQuery.extended_query_info.stmt_global_id != CurrentQuery.extended_query_info.stmt_info->statement_id) {
								PROXY_TRACE();
								assert(0);
							}
							previous_status.push(status);
							NEXT_IMMEDIATE(PROCESSING_STMT_PREPARE);
						}
						CurrentQuery.extended_query_info.stmt_backend_id = backend_stmt_id;
					}
				}
			}
			// Swtich to fast forward mode if the query matches copy ... stdin command
			re2::StringPiece matched;
			const char* query_to_match = (CurrentQuery.get_digest_text() ? CurrentQuery.get_digest_text() : (char*)CurrentQuery.QueryPointer);
			if (copy_cmd_matcher->match(query_to_match, &matched)) {
				switch_normal_to_fast_forward_mode(pkt, std::string(matched.data(), matched.size()), SESSION_FORWARD_TYPE_COPY_FROM_STDIN_STDOUT);
				break;
			}
			if (myconn->async_state_machine == ASYNC_IDLE) {
				SetQueryTimeout();
			}
			int rc;
			timespec begint;
			if (thread->variables.stats_time_backend_query) {
				clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begint);
			}
			rc = RunQuery(myds, myconn);
			timespec endt;
			if (thread->variables.stats_time_backend_query) {
				clock_gettime(CLOCK_THREAD_CPUTIME_ID, &endt);
				thread->status_variables.stvar[st_var_backend_query_time] = thread->status_variables.stvar[st_var_backend_query_time] +
					(endt.tv_sec * 1000000000 + endt.tv_nsec) -
					(begint.tv_sec * 1000000000 + begint.tv_nsec);
			}

			if (rc == 0) {

				if (active_transactions != 0) {  // run this only if currently we think there is a transaction
					if (myconn->IsKnownActiveTransaction() == false) { // there is no transaction on the backend connection
						active_transactions = NumActiveTransactions(); // we check all the hostgroups/backends
						if (active_transactions == 0)
							transaction_started_at = 0; // reset it
					}
				}

				// if we are locked on hostgroup, the value of autocommit is copied from the backend connection
				// see bug #3549
				if (locked_on_hostgroup >= 0) {
					assert(myconn != NULL);
					assert(myconn->pgsql_conn != NULL);
					//autocommit = myconn->pgsql->server_status & SERVER_STATUS_AUTOCOMMIT;
				}

				switch (status) {
				case PROCESSING_STMT_EXECUTE:
				case PROCESSING_QUERY:
					PgSQL_Result_to_PgSQL_wire(myconn, myconn->myds);
					break;
				case PROCESSING_STMT_PREPARE:
				{
					enum session_status st;
					if (handler___rc0_PROCESSING_STMT_PREPARE(st, myds)) {
						NEXT_IMMEDIATE(st);
					}
				}
				break;
				case PROCESSING_STMT_DESCRIBE:
					handler___rc0_PROCESSING_STMT_DESCRIBE_PREPARE(myds);
					break;
				// Handled in PROCESSING_QUERY
				//case PROCESSING_STMT_EXECUTE:
				//	PgSQL_Result_to_PgSQL_wire(myconn, myconn->myds);
				//	break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
				}

				// if we are in extended query mode, we need to check if we have a pending extended query messages
				bool has_pending_messages = false;
				if (processing_extended_query) {
					has_pending_messages = (extended_query_frame.empty() == false);
					
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p client_myds=%p server_myds=%p myconn=%p Remaining extended query messages '%lu'."
						"Sticky Backend='%s'\n",
						this, client_myds, myds, myconn, extended_query_frame.size(), (has_pending_messages ? "yes" : "no"));

					if (!has_pending_messages) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Extended query sync completed for session %p\n", this);
						bind_waiting_for_execute.reset(nullptr);
					}
#ifdef DEBUG
					if (dbg_extended_query_backend_conn)
						assert(dbg_extended_query_backend_conn == myconn);

					if (has_pending_messages) {
						dbg_extended_query_backend_conn = myconn;
					}
#endif
				} 

				RequestEnd(myds);
				finishQuery(myds, myconn, has_pending_messages);

				if (has_pending_messages) {
					// check if there are messages remaining in extended_query_frame, 
					// if yes, send response to client and process pending messages
					writeout();
					NEXT_IMMEDIATE(PROCESSING_EXTENDED_QUERY_SYNC);
				}
			} else {
				if (rc == -1) {
					// the query failed
					//bool is_error_present = myconn->is_error_present(); // false means failure is due to server being in OFFLINE state
					PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, 9999); // TOFIX
					//CurrentQuery.mysql_stmt = NULL; // immediately reset mysql_stmt
					int rc1 = handler_ProcessingQueryError_CheckBackendConnectionStatus(myds);
					if (rc1 == -1) {
						handler_ret = -1;
						return handler_ret;
					}
					else {
						if (rc1 == 1)
							NEXT_IMMEDIATE(CONNECTING_SERVER);
					}
					if (myconn->is_connection_in_reusable_state() == false) {
						if (handler_minus1_ClientLibraryError(myds)) {
							NEXT_IMMEDIATE(CONNECTING_SERVER);
						} else {
							handler_ret = -1;
							return handler_ret;
						}
					} else {
						handler_minus1_LogErrorDuringQuery(myconn);
						if (handler_minus1_HandleErrorCodes(myds, handler_ret)) {
							if (handler_ret == 0)
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							return handler_ret;
						}
						handler_minus1_GenerateErrorMessage(myds, wrong_pass);
						RequestEnd(myds);
						handler_minus1_HandleBackendConnection(myds);
					}
				} else {
					switch (rc) {
						// rc==1 , query is still running
						// start sending to frontend if pgsql_thread___threshold_resultset_size is reached
					case 1:
						if (myconn->query_result && myconn->query_result->get_resultset_size() > (unsigned int)pgsql_thread___threshold_resultset_size) {
							myconn->query_result->get_resultset(client_myds->PSarrayOUT);
						}
						break;
						// rc==2 : a multi-resultset (or multi statement) was detected, and the current statement is completed
					case 2:
						PgSQL_Result_to_PgSQL_wire(myconn, myconn->myds);
						if (myconn->query_result) { // we also need to clear query_result, so that the next statement will recreate it if needed
							if (myconn->query_result_reuse) {
								delete myconn->query_result_reuse;
							}
							myconn->query_result_reuse = myconn->query_result;
							myconn->query_result = NULL;
						}
						NEXT_IMMEDIATE(PROCESSING_QUERY);
						break;
						// rc==3 , a multi statement query is still running
						// start sending to frontend if pgsql_thread___threshold_resultset_size is reached
					case 3:
						if (myconn->query_result && myconn->query_result->get_resultset_size() > (unsigned int)pgsql_thread___threshold_resultset_size) {
							myconn->query_result->get_resultset(client_myds->PSarrayOUT);
						}
						break;
					default:
						break;
					}
				}

				// query has failed
				if (processing_extended_query && // we are processing extended query message
					rc != 1) { // rc == 1 means query is still running, we don't reset the extended_query_frame
					// we discard all pending messages
					reset_extended_query_frame();
					// status remains unchanged
				}
			}
			goto __exit_DSS__STATE_NOT_INITIALIZED;
		}
		break;

	case SETTING_ISOLATION_LEVEL:
	case SETTING_TRANSACTION_READ:
	case SETTING_VARIABLE:
	case SETTING_NEXT_ISOLATION_LEVEL:
	case SETTING_NEXT_TRANSACTION_READ:
	{
		int rc = 0;
		if (pgsql_variables.update_variable(this, status, rc)) {
			goto handler_again;
		}
		if (rc == -1) {
			handler_ret = -1;
			return handler_ret;
		}
	}
	break;
	case CONNECTING_SERVER:
	{
		int rc = 0;
		if (handler_again___status_CONNECTING_SERVER(&rc))
			goto handler_again;	// we changed status
		if (rc == 1) //handler_again___status_CONNECTING_SERVER returns 1
			goto __exit_DSS__STATE_NOT_INITIALIZED;
	}
	break;
	case session_status___NONE:
		fprintf(stderr, "NONE\n");
	default:
	{
		int rc = 0;
		if (handler_again___multiple_statuses(&rc)) // a sort of catch all
			goto handler_again;	// we changed status
		if (rc == -1) { // we have an error we can't handle
			handler_ret = -1;
			return handler_ret;
		}
	}
	break;
	}


__exit_DSS__STATE_NOT_INITIALIZED:


	if (mybe && mybe->server_myds) {
		if (mybe->server_myds->DSS > STATE_MARIADB_BEGIN && mybe->server_myds->DSS < STATE_MARIADB_END) {
#ifdef DEBUG
			PgSQL_Data_Stream* myds = mybe->server_myds;
			PgSQL_Connection* myconn = mybe->server_myds->myconn;
#endif /* DEBUG */
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
		}
	}

	writeout();

	if (wrong_pass == true) {
		client_myds->array2buffer_full();
		client_myds->write_to_net();
		handler_ret = -1;
		return handler_ret;
	}
	handler_ret = 0;
	return handler_ret;
}
// end ::handler()


bool PgSQL_Session::handler_again___multiple_statuses(int* rc) {
	bool ret = false;
	switch (status) {
	case RESETTING_CONNECTION_V2:
		ret = handler_again___status_RESETTING_CONNECTION(rc);
		break;
	// TODO: fix this
	//case SETTING_INIT_CONNECT:
	//	ret = handler_again___status_SETTING_INIT_CONNECT(rc);
		break;
	default:
		break;
	}
	return ret;
}

void PgSQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t* pkt, bool* wrong_pass) {
	bool is_encrypted = client_myds->encrypted;
	bool handshake_response_return = false;
	bool ssl_request = false;
	
	if (client_myds->auth_received_startup == false) {
		if (client_myds->myprot.process_startup_packet((unsigned char*)pkt->ptr, pkt->size, ssl_request) == true ) {
			if (ssl_request) {
				if (is_encrypted == false && client_myds->encrypted == true) {
					// switch to SSL...
				} else {
					// if sslmode is prefer, same connection will be used for plain text
					l_free(pkt->size, pkt->ptr);
					return;
				}
			} else if (client_myds->myprot.generate_pkt_initial_handshake(true, NULL, NULL, &thread_session_id, true) == true) {
				client_myds->auth_received_startup = true;
				l_free(pkt->size, pkt->ptr);
				return;
			} else {
				assert(0); // this should never happen
			}
		} else {
			*wrong_pass = true; //to forcefully close the connection. Is there a better way to do it?
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			l_free(pkt->size, pkt->ptr);
			return;
		}
	} 
	
	bool handshake_err = true;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p , handshake_response=%d , switching_auth_stage=%d , is_encrypted=%d , client_encrypted=%d\n", this, client_myds, handshake_response_return, client_myds->switching_auth_stage, is_encrypted, client_myds->encrypted);
	
	if (client_myds->auth_received_startup) {
		EXECUTION_STATE state = client_myds->myprot.process_handshake_response_packet((unsigned char*)pkt->ptr, pkt->size);

		if (state == EXECUTION_STATE::PENDING) {
			l_free(pkt->size, pkt->ptr);
			return;
		}
		
		handshake_response_return = (state == EXECUTION_STATE::SUCCESSFUL) ? true : false;
	}
	
	if (
		(handshake_response_return == false) && (client_myds->switching_auth_stage == 1)
		) {
		l_free(pkt->size, pkt->ptr);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p . Returning\n", this, client_myds);
		return;
	}

	if (
		(is_encrypted == false) && // the connection was encrypted
		(handshake_response_return == false) && // the authentication didn't complete
		(client_myds->encrypted == true) // client is asking for encryption
		) {
			// use SSL
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p . SSL_INIT\n", this, client_myds);
			client_myds->DSS = STATE_SSL_INIT;
			client_myds->rbio_ssl = BIO_new(BIO_s_mem());
			client_myds->wbio_ssl = BIO_new(BIO_s_mem());
			client_myds->ssl = GloVars.get_SSL_new();
			SSL_set_fd(client_myds->ssl, client_myds->fd);
			SSL_set_accept_state(client_myds->ssl);
			SSL_set_bio(client_myds->ssl, client_myds->rbio_ssl, client_myds->wbio_ssl);
			l_free(pkt->size, pkt->ptr);
			proxysql_keylog_attach_callback(GloVars.get_SSL_ctx());
			return;
	}

	if (
		//(client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size)==true)
		(handshake_response_return == true)
		&&
		(
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
			(default_hostgroup < 0 && (session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS || session_type == PROXYSQL_SESSION_SQLITE))
#else
			(default_hostgroup < 0 && (session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS))
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
			||
			(default_hostgroup == 0 && session_type == PROXYSQL_SESSION_CLICKHOUSE)
			||
			//(default_hostgroup>=0 && session_type == PROXYSQL_SESSION_PGSQL)
			(default_hostgroup >= 0 && (session_type == PROXYSQL_SESSION_PGSQL || session_type == PROXYSQL_SESSION_SQLITE))
			||
			(
				client_myds->encrypted == false
				&&
				strncmp(client_myds->myconn->userinfo->username, pgsql_thread___monitor_username, strlen(pgsql_thread___monitor_username)) == 0
				)
			) // Do not delete this line. See bug #492
		) {
		if (session_type == PROXYSQL_SESSION_ADMIN) {
			if ((default_hostgroup < 0) || (strncmp(client_myds->myconn->userinfo->username, pgsql_thread___monitor_username, strlen(pgsql_thread___monitor_username)) == 0)) {
				if (default_hostgroup == STATS_HOSTGROUP) {
					session_type = PROXYSQL_SESSION_STATS;
				}
			}
		}
		l_free(pkt->size, pkt->ptr);
		//if (client_myds->encrypted==false) {
		assert(client_myds->myconn->userinfo->dbname);

		int free_users = 0;
		int used_users = 0;
		if (
			(max_connections_reached == false)
			&&
			(session_type == PROXYSQL_SESSION_PGSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE || session_type == PROXYSQL_SESSION_SQLITE)
			) {
			//if (session_type == PROXYSQL_SESSION_PGSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE) {
			client_authenticated = true;
			switch (session_type) {
			case PROXYSQL_SESSION_SQLITE:
				//#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
				free_users = 1;
				break;
				//#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
			case PROXYSQL_SESSION_PGSQL:
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p , session_type=PROXYSQL_SESSION_PGSQL\n", this, client_myds);
				if (use_ldap_auth == false) {
					free_users = GloPgAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
				}
				else {
					free_users = GloMyLdapAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->fe_username, &used_users);
				}
				break;
#ifdef PROXYSQLCLICKHOUSE
			case PROXYSQL_SESSION_CLICKHOUSE:
				free_users = GloClickHouseAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
				break;
#endif /* PROXYSQLCLICKHOUSE */
			default:
				// LCOV_EXCL_START
				assert(0);
				break;
				// LCOV_EXCL_STOP
			}
		}
		else {
			free_users = 1;
		}
		if (max_connections_reached == true || free_users <= 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p , max_connections_reached=%d , free_users=%d\n", this, client_myds, max_connections_reached, free_users);
			client_authenticated = false;
			*wrong_pass = true;
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			uint8_t _pid = 2;
			if (client_myds->switching_auth_stage) _pid += 2;
			if (max_connections_reached == true) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p , Too many connections\n", this, client_myds);
				client_myds->myprot.generate_error_packet(true, false, "Too many connections", PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS,
					true, true);
				proxy_warning("pgsql-max_connections reached. Returning 'Too many connections'\n");
				GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, (char*)"pgsql-max_connections reached");
				__sync_fetch_and_add(&PgHGM->status.access_denied_max_connections, 1);
			}
			else { // see issue #794
				__sync_fetch_and_add(&PgHGM->status.access_denied_max_user_connections, 1);
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . User '%s' has exceeded the 'max_user_connections' resource (current value: %d)\n", this, client_myds, client_myds->myconn->userinfo->username, used_users);
				char* a = (char*)"User '%s' has exceeded the 'max_user_connections' resource (current value: %d)";
				char* b = (char*)malloc(strlen(a) + strlen(client_myds->myconn->userinfo->username) + 16);
				sprintf(b, a, client_myds->myconn->userinfo->username, used_users);
				GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
				client_myds->myprot.generate_error_packet(true, false, b, PGSQL_ERROR_CODES::ERRCODE_TOO_MANY_CONNECTIONS,
					true, true);
				proxy_warning("User '%s' has exceeded the 'max_user_connections' resource (current value: %d)\n", client_myds->myconn->userinfo->username, used_users);
				free(b);
			}
			__sync_add_and_fetch(&PgHGM->status.client_connections_aborted, 1);
			client_myds->DSS = STATE_SLEEP;
		}
		else {
			if (
				(default_hostgroup == ADMIN_HOSTGROUP && strcmp(client_myds->myconn->userinfo->username, (char*)"admin") == 0)
				||
				(default_hostgroup == STATS_HOSTGROUP && strcmp(client_myds->myconn->userinfo->username, (char*)"stats") == 0)
				||
				(default_hostgroup < 0 && strcmp(client_myds->myconn->userinfo->username, (char*)"monitor") == 0)
				) {
				char* client_addr = NULL;
				union {
					struct sockaddr_in in;
					struct sockaddr_in6 in6;
				} custom_sockaddr;
				struct sockaddr* addr = (struct sockaddr*)malloc(sizeof(custom_sockaddr));
				socklen_t addrlen = sizeof(custom_sockaddr);
				memset(addr, 0, sizeof(custom_sockaddr));
				int rc = 0;
				rc = getpeername(client_myds->fd, addr, &addrlen);
				if (rc == 0) {
					char buf[512];
					switch (addr->sa_family) {
					case AF_INET: {
						struct sockaddr_in* ipv4 = (struct sockaddr_in*)addr;
						inet_ntop(addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
						client_addr = strdup(buf);
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)addr;
						inet_ntop(addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
						client_addr = strdup(buf);
						break;
					}
					default:
						client_addr = strdup((char*)"localhost");
						break;
					}
				}
				else {
					client_addr = strdup((char*)"");
				}
				uint8_t _pid = 2;
				if (client_myds->switching_auth_stage) _pid += 2;
				if (is_encrypted) _pid++;
				if (
					(strcmp(client_addr, (char*)"127.0.0.1") == 0)
					||
					(strcmp(client_addr, (char*)"localhost") == 0)
					||
					(strcmp(client_addr, (char*)"::1") == 0)
					) {
					// we are good!
					client_myds->myprot.welcome_client();
					handshake_err = false;
					GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
					status = WAITING_CLIENT_DATA;
					client_myds->DSS = STATE_CLIENT_AUTH_OK;
				}
				else {
					char* a = (char*)"User '%s' can only connect locally";
					char* b = (char*)malloc(strlen(a) + strlen(client_myds->myconn->userinfo->username));
					sprintf(b, a, client_myds->myconn->userinfo->username);
					GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
					client_myds->myprot.generate_error_packet(true, false, b, PGSQL_ERROR_CODES::ERRCODE_SQLSERVER_REJECTED_ESTABLISHMENT_OF_SQLCONNECTION,
						true, true);
					free(b);
				}
				free(addr);
				free(client_addr);
			}
			else {
				uint8_t _pid = 2;
				if (client_myds->switching_auth_stage) _pid += 2;
				if (is_encrypted) _pid++;
				// If this condition is met, it means that the
				// 'STATE_SERVER_HANDSHAKE' being performed isn't from the start of a
				// connection, but as a consequence of a 'COM_USER_CHANGE' which
				// requires an 'Auth Switch'. Thus, we impose a 'pid' of '3' for the
				// response 'OK' packet. See #3504 for more context.
				if (change_user_auth_switch) {
					_pid = 3;
					change_user_auth_switch = 0;
				}
				if (use_ssl == true && is_encrypted == false) {
					*wrong_pass = true;
					GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);

					char* _a = (char*)"ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required";
					char* _s = (char*)malloc(strlen(_a) + strlen(client_myds->myconn->userinfo->username) + 32);
					sprintf(_s, _a, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
					client_myds->myprot.generate_error_packet(true, false, _s, PGSQL_ERROR_CODES::ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION,
							true, true);
					proxy_error("ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required\n", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p . Access denied for user '%s' (using password: %s). SSL is required\n", this, client_myds, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
					__sync_add_and_fetch(&PgHGM->status.client_connections_aborted, 1);
					free(_s);
					__sync_fetch_and_add(&PgHGM->status.access_denied_wrong_password, 1);
				}
				else {
					// we are good!
					//client_myds->myprot.generate_pkt_OK(true,NULL,NULL, (is_encrypted ? 3 : 2), 0,0,0,0,NULL,false);
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 8, "Session=%p , DS=%p . STATE_CLIENT_AUTH_OK\n", this, client_myds);
					GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
					client_myds->myprot.welcome_client();
					handshake_err = false;
					status = WAITING_CLIENT_DATA;
					client_myds->DSS = STATE_CLIENT_AUTH_OK;
				}
			}
		}
	}
	else {
		l_free(pkt->size, pkt->ptr);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Wrong credentials for frontend: disconnecting\n", this, client_myds);
		*wrong_pass = true;
		// FIXME: this should become close connection
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		char* client_addr = NULL;
		if (client_myds->client_addr && client_myds->myconn->userinfo->username) {
			char buf[512];
			switch (client_myds->client_addr->sa_family) {
			case AF_INET: {
				struct sockaddr_in* ipv4 = (struct sockaddr_in*)client_myds->client_addr;
				if (ipv4->sin_port) {
					inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
					client_addr = strdup(buf);
				}
				else {
					client_addr = strdup((char*)"localhost");
				}
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)client_myds->client_addr;
				inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
				client_addr = strdup(buf);
				break;
			}
			default:
				client_addr = strdup((char*)"localhost");
				break;
			}
		}
		else {
			client_addr = strdup((char*)"");
		}
		if (client_myds->myconn->userinfo->username && client_myds->myconn->userinfo->username[0] != '\0') {
			char* _s = (char*)malloc(strlen(client_myds->myconn->userinfo->username) + 100 + strlen(client_addr));
			uint8_t _pid = 2;
			if (client_myds->switching_auth_stage) _pid += 2;
			if (is_encrypted) _pid++;
#ifdef DEBUG
			if (client_myds->myconn->userinfo->password) {
				char* tmp_pass = strdup(client_myds->myconn->userinfo->password);
				int lpass = strlen(tmp_pass);
				for (int i = 2; i < lpass - 1; i++) {
					tmp_pass[i] = '*';
				}
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Error: Access denied for user '%s'@'%s' , Password='%s'. Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr, tmp_pass);
				free(tmp_pass);
			}
			else {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Error: Access denied for user '%s'@'%s' . No password. Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr);
			}
#endif // DEBUG
			sprintf(_s, "ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			client_myds->myprot.generate_error_packet(true, false, _s, PGSQL_ERROR_CODES::ERRCODE_INVALID_PASSWORD, true, true);
			proxy_error("%s\n", _s);
			free(_s);
			__sync_fetch_and_add(&PgHGM->status.access_denied_wrong_password, 1);
		}
		if (client_addr) {
			free(client_addr);
		}
		GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);
		__sync_add_and_fetch(&PgHGM->status.client_connections_aborted, 1);
		client_myds->DSS = STATE_SLEEP;
	}

	if (pgsql_thread___client_host_cache_size) {
		GloPTH->update_client_host_cache(client_myds->client_addr, handshake_err);
	}
}

#if 0
// Note: as commented in issue #546 and #547 , some clients ignore the status of CLIENT_MULTI_STATEMENTS
// therefore tracking it is not needed, unless in future this should become a security enhancement,
// returning errors to all clients trying to send multi-statements .
// see also #1140
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t* pkt) {
	
	char v;
	v = *((char*)pkt->ptr + 3);
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_SET_OPTION packet , value %d\n", v);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx = NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;

	bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
	if (deprecate_eof_active)
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL, true);
	else
		client_myds->myprot.generate_pkt_EOF(true, NULL, NULL, 1, 0, setStatus);

	if (v == 1) { // disabled. MYSQL_OPTION_MULTI_STATEMENTS_OFF == 1
		client_myds->myconn->options.client_flag &= ~CLIENT_MULTI_STATEMENTS;
	}
	else { // enabled, MYSQL_OPTION_MULTI_STATEMENTS_ON == 0
		client_myds->myconn->options.client_flag |= CLIENT_MULTI_STATEMENTS;
	}
	client_myds->DSS = STATE_SLEEP;
	l_free(pkt->size, pkt->ptr);
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t* pkt) {

	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_PING packet\n");
	l_free(pkt->size, pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx = NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
	client_myds->DSS = STATE_SLEEP;
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t* pkt) {
	if (session_type == PROXYSQL_SESSION_PGSQL) {
		/* FIXME: temporary */
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, true, "Command not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
	}
	else {
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, true, "Command not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
	}
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t* pkt) {
	l_free(pkt->size, pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_error_packet(true, true, "Command not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, false);
	client_myds->DSS = STATE_SLEEP;
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t* pkt) {
	
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
	if (session_type == PROXYSQL_SESSION_PGSQL) {
		//__sync_fetch_and_add(&PgHGM->status.frontend_init_db, 1);
		//client_myds->myconn->userinfo->set_dbname((char*)pkt->ptr + sizeof(mysql_hdr) + 1, pkt->size - sizeof(mysql_hdr) - 1);
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx = NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
		GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_INITDB, this, NULL);
		client_myds->DSS = STATE_SLEEP;
	}
	else {
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx = NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
		client_myds->DSS = STATE_SLEEP;
	}
}

// this function was introduced due to isseu #718
// some application (like the one written in Perl) do not use COM_INIT_DB , but COM_QUERY with USE dbname
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t* pkt) {
	
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUERY with USE dbname\n");
	if (session_type == PROXYSQL_SESSION_PGSQL) {
		//__sync_fetch_and_add(&PgHGM->status.frontend_use_db, 1);
		string nq = string((char*)pkt->ptr + sizeof(mysql_hdr) + 1, pkt->size - sizeof(mysql_hdr) - 1);
		RE2::GlobalReplace(&nq, (char*)"(?U)/\\*.*\\*/", (char*)" ");
		char* sn_tmp = (char*)nq.c_str();
		while (sn_tmp < (nq.c_str() + nq.length() - 4) && *sn_tmp == ' ')
			sn_tmp++;
		//char *schemaname=strdup(nq.c_str()+4);
		char* schemaname = strdup(sn_tmp + 3);
		char* schemanameptr = trim_spaces_and_quotes_in_place(schemaname);
		// handle cases like "USE `schemaname`
		if (schemanameptr[0] == '`' && schemanameptr[strlen(schemanameptr) - 1] == '`') {
			schemanameptr[strlen(schemanameptr) - 1] = '\0';
			schemanameptr++;
		}
		//client_myds->myconn->userinfo->set_dbname(schemanameptr);
		free(schemaname);
		if (mirror == false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx = NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
		GloPgSQL_Logger->log_audit_entry(PROXYSQL_MYSQL_INITDB, this, NULL);
		client_myds->DSS = STATE_SLEEP;
	}
	else {
		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx = NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
		client_myds->DSS = STATE_SLEEP;
	}
}
#endif

// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo
void PgSQL_Session::handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t* pkt) {
	if (pkt->size == 0)
		return; // nothing to rewrite

	const char msg_type = *((char*)pkt->ptr);
	bool stats_enabled = thread->variables.stats_time_query_processor;

	auto start_timer = [&]() -> timespec {
		timespec t{};
		if (stats_enabled)
			clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
		return t;
		};

	auto stop_timer = [&](const timespec& begin) {
		if (!stats_enabled) return;
		timespec end{};
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end);
		thread->status_variables.stvar[st_var_query_processor_time] +=
			(end.tv_sec * 1000000000 + end.tv_nsec) -
			(begin.tv_sec * 1000000000 + begin.tv_nsec);
		};

	if (msg_type == 'Q') {
		// Free old packet before building new one
		l_free(pkt->size, pkt->ptr);

		timespec begint = start_timer();

		PG_pkt pgpkt(1 + 4 + qpo->new_query->length() + 1);
		pgpkt.put_char('Q');
		pgpkt.put_uint32(4 + qpo->new_query->length() + 1);
		pgpkt.put_bytes(qpo->new_query->data(), qpo->new_query->length());
		pgpkt.put_char('\0');

		auto buff = pgpkt.detach();
		pkt->ptr = buff.first;
		pkt->size = buff.second;

		CurrentQuery.query_parser_free();
		CurrentQuery.begin(reinterpret_cast<unsigned char*>(pkt->ptr), pkt->size, true);

		delete qpo->new_query;
		stop_timer(begint);
		return;
	}

	if (msg_type == 'P') {
		timespec begint = start_timer();

		// Parse the original packet before rewriting
		PgSQL_Parse_Message orig_parse_msg;
		if (!orig_parse_msg.parse(*pkt)) {
			assert(0); // should never happen
		}
		const auto& orig_data = orig_parse_msg.data();

		unsigned int new_query_size = qpo->new_query->length();
		unsigned int old_query_size = strlen(orig_data.query_string);
		unsigned int new_pkt_size = orig_parse_msg.get_raw_pkt().size + (new_query_size - old_query_size);

		PG_pkt pgpkt(new_pkt_size);
		pgpkt.put_char('P');
		pgpkt.put_uint32(new_pkt_size - 1);
		pgpkt.put_string(orig_data.stmt_name);
		pgpkt.put_string(qpo->new_query->c_str());
		pgpkt.put_uint16(orig_data.num_param_types);
		if (orig_data.num_param_types) {
			pgpkt.put_bytes(orig_data.param_types_start_ptr,
				orig_data.num_param_types * sizeof(uint32_t));
		}

		auto buff = pgpkt.detach();
		pkt->ptr = buff.first;
		pkt->size = buff.second;

		delete qpo->new_query;

		// Parse the new rewritten packet
		PgSQL_Parse_Message new_parse_msg;
		if (!new_parse_msg.parse(*pkt)) {
			assert(0); // should never happen
		}
		const auto& new_data = new_parse_msg.data();

		CurrentQuery.query_parser_free();
		CurrentQuery.begin((unsigned char*)new_data.query_string,
			strlen(new_data.query_string) + 1, false);
		CurrentQuery.extended_query_info.stmt_client_name = new_data.stmt_name;

		if (new_data.num_param_types > 0) {
			Parse_Param_Types parse_param_type(new_data.num_param_types);
			auto param_type_reader = new_parse_msg.get_param_types_reader();
			for (uint16_t i = 0; i < new_data.num_param_types; ++i) {
				if (!param_type_reader.next(&parse_param_type[i])) {
					proxy_error("Failed to read result format at index %u\n", i);
					assert(0);
				}
			}
			CurrentQuery.extended_query_info.parse_param_types = std::move(parse_param_type);
		}

		// parse() takes ownership of the packet, so pkt is replaced here
		*pkt = new_parse_msg.detach();

		stop_timer(begint);
		return;
	}

	// Should never happen
	assert(0);
}

// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo
void PgSQL_Session::handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t* pkt) {
	
	client_myds->DSS = STATE_QUERY_SENT_NET;
	unsigned int nTrx = NumActiveTransactions();
	const char txn_state = (nTrx ? 'T' : 'I');
	client_myds->myprot.generate_ok_packet(true, true, qpo->OK_msg, 0, (const char*)pkt->ptr + 5, txn_state);
	RequestEnd(NULL);
	l_free(pkt->size, pkt->ptr);
}

// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo
void PgSQL_Session::handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t* pkt) {
	client_myds->DSS = STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_error_packet(true, true, qpo->error_msg, 
		PGSQL_ERROR_CODES::ERRCODE_INSUFFICIENT_PRIVILEGE, false);
	RequestEnd(NULL);
	l_free(pkt->size, pkt->ptr);
}

// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo
void PgSQL_Session::handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t* pkt) {
	// ER_NET_PACKET_TOO_LARGE
	client_myds->DSS = STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_error_packet(true, true, "Got a packet bigger than 'max_allowed_packet' bytes",
		PGSQL_ERROR_CODES::ERRCODE_PROGRAM_LIMIT_EXCEEDED, false);
	RequestEnd(NULL);
	l_free(pkt->size, pkt->ptr);
}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(PtrSize_t* pkt, bool* lock_hostgroup, PgSQL_Extended_Query_Type stmt_type) {
	/*
		lock_hostgroup:
			If this variable is set to true, this session will get lock to a
			specific hostgroup, and also have multiplexing disabled.
			It means that parsing the query wasn't completely possible (mostly
			a SET statement) and proxysql won't be able to set the same variable
			in another connection.
			This algorithm will be become obsolete once we implement session
			tracking for MySQL 5.7+
	*/
	//bool exit_after_SetParse = true;
	
	if (qpo->new_query) {
		handler_WCD_SS_MCQ_qpo_QueryRewrite(pkt);
	}

	if (pkt->size > (unsigned int)pgsql_thread___max_allowed_packet) {
		handler_WCD_SS_MCQ_qpo_LargePacket(pkt);
		return true;
	}

	if (qpo->OK_msg) {
		handler_WCD_SS_MCQ_qpo_OK_msg(pkt);
		return true;
	}

	if (qpo->error_msg) {
		handler_WCD_SS_MCQ_qpo_error_msg(pkt);
		return true;
	}

    // Check if the session is not locked on a hostgroup and there are untracked option parameters
    if (locked_on_hostgroup < 0 && untracked_option_parameters.empty() == false) {
        if (client_myds && client_myds->addr.addr) {
            proxy_warning("Unknown connection options from client %s:%d. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", client_myds->addr.addr, client_myds->addr.port, untracked_option_parameters.c_str());
        } else {
            // Log a warning message without client address and port
            proxy_warning("Unknown connection options. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", untracked_option_parameters.c_str());
        }

        // If there are untracked option parameters, lock the hostgroup
        *lock_hostgroup = true;

        // Always create a new connection to pass untracked options to the server
        qpo->create_new_conn = true;
        return false;
    }

	if (stmt_type == PGSQL_EXTENDED_QUERY_TYPE_PARSE ||
		stmt_type == PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE) {	// for Parse and Describe we exit here
		goto __exit_set_destination_hostgroup;
	}

	// handle here #509, #815 and #816
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char* dig = CurrentQuery.QueryParserArgs.digest_text;

		if ((locked_on_hostgroup == -1) && (strncasecmp(dig, "SET ", 4) == 0)) {
			// this code is executed only if locked_on_hostgroup is not set yet
			// if locked_on_hostgroup is set, we do not try to parse the SET statement
#ifdef DEBUG
			{
				string nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig, ';') && (index(dig, ';') != dig + strlen(dig) - 1)) {
				string nqn;
				if (pgsql_thread___parse_failure_logs_digest)
					nqn = string(CurrentQuery.get_digest_text());
				else
					nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_warning(
					"Unable to parse multi-statements command with SET statement from client"
					" %s:%d: setting lock hostgroup. Command: %s\n", client_myds->addr.addr,
					client_myds->addr.port, nqn.c_str()
				);
				*lock_hostgroup = true;
				return false;
			}
			
			string nq = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
			RE2::GlobalReplace(&nq, "^/\\*!\\d\\d\\d\\d\\d SET(.*)\\*/", "SET\\1");
			RE2::GlobalReplace(&nq, "(?U)/\\*.*\\*/", "");
			// remove trailing space and semicolon if present. See issue#4380
			nq.erase(nq.find_last_not_of(" ;") + 1);
			if (
				(match_regexes && match_regexes[1]->match(dig))
				) 
			{
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Parsing SET command %s\n", nq.c_str());
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nq.c_str());
				PgSQL_Set_Stmt_Parser parser(nq);
				std::map<std::string, std::vector<std::string>> set = {};
				std::vector<std::pair<std::string, std::string>> param_status = {};
				bool send_param_status = false;

				thread->thr_SetParser->set_query(nq); // replace the query
				set = thread->thr_SetParser->parse1v2(); // use algorithm v2

				// Flag to be set if any variable within the 'SET' statement fails to be tracked,
				// due to being unknown or because it's an user defined variable.
				bool failed_to_parse_var = set.empty();
				for (auto it = std::begin(set); it != std::end(set); ++it) {
					std::string var = it->first;
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
					if (it->second.size() < 1 || it->second.size() > 2) {
						// error not enough arguments
						string query_str = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
						string digest_str = string(CurrentQuery.get_digest_text());
						string nqn;
						if (pgsql_thread___parse_failure_logs_digest)
							nqn = digest_str;
						else
							nqn = query_str;
						// PMC-10002: A query has failed to be parsed. This can be due a incorrect query or
						// due to ProxySQL not being able to properly parse it. In case the query is correct a
						// bug report should be filed including the offending query.
						proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n",
							query_str.c_str());
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
					auto values = std::begin(it->second);
					if (std::find(pgsql_critical_variables.begin(), pgsql_critical_variables.end(), var) != pgsql_critical_variables.end() ||
						pgsql_other_variables.find(var) != pgsql_other_variables.end()) {
						std::string value1 = *values;

						int idx = PGSQL_NAME_LAST_HIGH_WM;
						for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
							// skip low water mark
							if (i == PGSQL_NAME_LAST_LOW_WM) continue;
							
							if (variable_name_exists(pgsql_tracked_variables[i], var.c_str()) == true) {
								idx = i;
								break;
							}
						}
						if (idx != PGSQL_NAME_LAST_HIGH_WM) {
							uint32_t current_hash = pgsql_variables.client_get_hash(this, idx);
							if ((value1.size() == sizeof("DEFAULT") - 1) && strncasecmp(value1.c_str(), "DEFAULT",sizeof("DEFAULT")-1) == 0) {
								auto [value, hash] = client_myds->myconn->get_startup_parameter_and_hash((enum pgsql_variable_name)idx);
								if (hash == 0)  {
									if (current_hash != 0) {
										proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Resetting connection variable %s to DEFAULT\n", var.c_str());
										pgsql_variables.client_reset_value(this, idx, true);
									}
									client_myds->DSS = STATE_QUERY_SENT_NET;
									unsigned int nTrx = NumActiveTransactions();
									const char trx_state = (nTrx ? 'T' : 'I');
									client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, trx_state, NULL, param_status);
									RequestEnd(NULL);
									l_free(pkt->size, pkt->ptr);
									return true;
								}
								value1 = value;
							}

							char* transformed_value = nullptr;
							if (pgsql_tracked_variables[idx].validator && pgsql_tracked_variables[idx].validator->validate &&
								(
									*pgsql_tracked_variables[idx].validator->validate)(
									value1.c_str(), &pgsql_tracked_variables[idx].validator->params, this, &transformed_value) == false
								) {
								char* m = NULL;
								char* errmsg = NULL;
								proxy_error("invalid value for parameter \"%s\": \"%s\"\n", pgsql_tracked_variables[idx].set_variable_name, value1.c_str());
								m = (char*)"invalid value for parameter \"%s\": \"%s\"";
								errmsg = (char*)malloc(value1.length() + strlen(pgsql_tracked_variables[idx].set_variable_name) +  strlen(m));
								sprintf(errmsg, m, pgsql_tracked_variables[idx].set_variable_name, value1.c_str());

								client_myds->DSS = STATE_QUERY_SENT_NET;
								client_myds->myprot.generate_error_packet(true, true, errmsg,
									PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE, false, true);
								free(errmsg);
								RequestEnd(NULL);
								l_free(pkt->size, pkt->ptr);
								return true;
							}

							if (transformed_value) {
								value1 = transformed_value;
								free(transformed_value);
							}

							if (idx == PGSQL_DATESTYLE) {
								if (value1.empty()) {
									client_myds->DSS = STATE_QUERY_SENT_NET;
									unsigned int nTrx = NumActiveTransactions();
									const char txn_state = (nTrx ? 'T' : 'I');
									client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, txn_state, NULL, param_status);
									RequestEnd(NULL);
									l_free(pkt->size, pkt->ptr);
									return true;
								}
							} 

							uint32_t var_hash_int = SpookyHash::Hash32(value1.c_str(), value1.length(), 10);
							if (current_hash != var_hash_int) {
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection %s to %s\n", var.c_str(), value1.c_str());
								if (!pgsql_variables.client_set_value(this, idx, value1.c_str(), true)) {
									return false;
								}
								if (idx == PGSQL_DATESTYLE) {
									// always set current_datestyle
									current_datestyle = PgSQL_DateStyle_Util::parse_datestyle(value1);
									// No need to set send_param_status to true, as the original DateStyle value may have been modified.  
								    // When send_param_status is true, it always sends the original value provided by the user in the SET statement.  
									if (IS_PGTRACKED_VAR_OPTION_SET_PARAM_STATUS(pgsql_tracked_variables[idx])) {
										param_status.emplace_back(var, value1);
									}
								} else {
									send_param_status = IS_PGTRACKED_VAR_OPTION_SET_PARAM_STATUS(pgsql_tracked_variables[idx]);
								}
							}
						}
					} else if (std::find(pgsql_variables.ignore_vars.begin(), pgsql_variables.ignore_vars.end(), var) != pgsql_variables.ignore_vars.end()) {
						// this is a variable we parse but ignore
						// see MySQL_Variables::MySQL_Variables() for a list of ignored variables
#ifdef DEBUG
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s value %s\n", var.c_str(), value1.c_str());
#endif // DEBUG
					} else {
						// At this point the variable is unknown to us, or it's a user variable
						// prefixed by '@', in both cases, we should fail to parse. We don't
						// fail inmediately so we can anyway keep track of the other variables
						// supplied within the 'SET' statement being parsed.
						failed_to_parse_var = true;
					}

					if (send_param_status)
						param_status.emplace_back(var, *values);
				}

				if (failed_to_parse_var) {
					unable_to_parse_set_statement(lock_hostgroup);
					return false;
				}

				client_myds->DSS = STATE_QUERY_SENT_NET;
				unsigned int nTrx = NumActiveTransactions();
				const char txn_state = (nTrx ? 'T' : 'I');
				client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, txn_state, NULL, param_status);
				RequestEnd(NULL);
				l_free(pkt->size, pkt->ptr);
				return true;
			} else {
				unable_to_parse_set_statement(lock_hostgroup);
				return false;
			}
		} else if ((locked_on_hostgroup == -1) && (strncasecmp(dig, "RESET ", 6) == 0)) {
#ifdef DEBUG
			{
				std::string nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing RESET command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig, ';') && (index(dig, ';') != dig + strlen(dig) - 1)) {
				string nqn;
				if (pgsql_thread___parse_failure_logs_digest)
					nqn = string(CurrentQuery.get_digest_text());
				else
					nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_warning(
					"Unable to parse multi-statements command with RESET statement from client"
					" %s:%d: setting lock hostgroup. Command: %s\n", client_myds->addr.addr,
					client_myds->addr.port, nqn.c_str()
				);
				*lock_hostgroup = true;
				return false;
			}

			string nq = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);

			RE2::GlobalReplace(&nq, "(?U)/\\*.*\\*/", "");
			RE2::GlobalReplace(&nq, "(?i)\\bRESET\\b", "");
			RE2::GlobalReplace(&nq, "[^\\w]*", "");

			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Parsing RESET command %s\n", nq.c_str());
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing RESET command = %s\n", nq.c_str());

			std::vector<std::pair<std::string, std::string>> param_status = {};

			if (strncasecmp(nq.c_str(), "ALL", 3) == 0) {

				for (int idx = 0; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {

					const char* name = pgsql_tracked_variables[idx].set_variable_name;
					auto [value, hash] = client_myds->myconn->get_startup_parameter_and_hash((enum pgsql_variable_name)idx);
					// hash can never be 0 for critical variables
					uint32_t current_hash = pgsql_variables.client_get_hash(this, idx);
					if (current_hash != hash) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection %s to %s\n", name, value);
						if (!pgsql_variables.client_set_value(this, idx, value, false)) {
							return false;
						}
						if (IS_PGTRACKED_VAR_OPTION_SET_PARAM_STATUS(pgsql_tracked_variables[idx])) {
							param_status.emplace_back(name, value);
						}
					}
				}

				for (int idx : client_myds->myconn->dynamic_variables_idx) {
					const char* name = pgsql_tracked_variables[idx].set_variable_name;
					auto [value, hash] = client_myds->myconn->get_startup_parameter_and_hash((enum pgsql_variable_name)idx);
					uint32_t current_hash = pgsql_variables.client_get_hash(this, idx);
					if (hash == 0 && current_hash != 0) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Resetting connection variable %s to DEFAULT\n", name);
						pgsql_variables.client_reset_value(this, idx, false);
					} else if (hash != 0 && current_hash != hash) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection %s to %s\n", name, value);
						if (!pgsql_variables.client_set_value(this, idx, value, false)) {
							return false;
						}
					}
				}
				client_myds->myconn->reorder_dynamic_variables_idx();

			} else if (std::find(pgsql_variables.ignore_vars.begin(), pgsql_variables.ignore_vars.end(), nq) != pgsql_variables.ignore_vars.end()) {
				// this is a variable we parse but ignore
#ifdef DEBUG
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing RESET %s\n", nq.c_str());
#endif // DEBUG
			} else {
				int idx = PGSQL_NAME_LAST_HIGH_WM;
				for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
					if (i == PGSQL_NAME_LAST_LOW_WM) 
						continue;

					if (variable_name_exists(pgsql_tracked_variables[i], nq.c_str()) == true) {
						idx = i;
						break;
					}
				}			
				if (idx != PGSQL_NAME_LAST_HIGH_WM) {
					const char* name = pgsql_tracked_variables[idx].set_variable_name;
					auto [value, hash] = client_myds->myconn->get_startup_parameter_and_hash((enum pgsql_variable_name)idx);
					uint32_t current_hash = pgsql_variables.client_get_hash(this, idx);
					// Reset to default if hash is zero, means startup parameter is not set
					if (hash == 0 && current_hash != 0) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Resetting connection variable %s to DEFAULT\n", name);
						pgsql_variables.client_reset_value(this, idx, true);
					} else if (hash != 0 && current_hash != hash) {
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection %s to %s\n", name, value);
						if (!pgsql_variables.client_set_value(this, idx, value, true)) {
							return false;
						}
						if (IS_PGTRACKED_VAR_OPTION_SET_PARAM_STATUS(pgsql_tracked_variables[idx])) {
							param_status.emplace_back(name, value);
						}
					}
				} else {
					unable_to_parse_set_statement(lock_hostgroup);
					return false;
				}
			}
			client_myds->DSS = STATE_QUERY_SENT_NET;
			unsigned int nTrx = NumActiveTransactions();
			const char txn_state = (nTrx ? 'T' : 'I');
			client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, txn_state, NULL, param_status);

			if (mirror == false) {
				RequestEnd(NULL);
			} else {
				client_myds->DSS = STATE_SLEEP;
				status = WAITING_CLIENT_DATA;
			}
			l_free(pkt->size, pkt->ptr);
			return true;
		} else if (strncasecmp(dig, "DISCARD ", 8) == 0) {
#ifdef DEBUG
			{
				std::string nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing DISCARD command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig, ';') && (index(dig, ';') != dig + strlen(dig) - 1)) {
				string nqn;
				if (pgsql_thread___parse_failure_logs_digest)
					nqn = string(CurrentQuery.get_digest_text());
				else
					nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_warning(
					"Unable to parse multi-statements command with DISCARD statement from client"
					" %s:%d: setting lock hostgroup. Command: %s\n", client_myds->addr.addr,
					client_myds->addr.port, nqn.c_str()
				);
				*lock_hostgroup = true;
				return false;
			}

			std::string nq = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);

			RE2::GlobalReplace(&nq, "(?U)/\\*.*\\*/", "");
			RE2::GlobalReplace(&nq, "(?i)\\bDISCARD\\b", "");
			RE2::GlobalReplace(&nq, "[^\\w]*", "");

			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Parsing DISCARD command %s\n", nq.c_str());
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing DISCARD command = %s\n", nq.c_str());
			bool handled = false;
			const char* discard_value = nq.c_str();
			if (strncasecmp(discard_value, "ALL", 3) == 0) {
				// Backup the current relevant session values
				int default_hostgroup = this->default_hostgroup;
				bool transaction_persistent = this->transaction_persistent;

				// Re-initialize the session
				reset();
				init();

				// Recover the relevant session values
				this->default_hostgroup = default_hostgroup;
				this->transaction_persistent = transaction_persistent;
				handled = true;
			} else if (strncasecmp(discard_value, "PLANS", 5) == 0) {
				// ignore
				handled = true;
			}

			if (handled) {
				client_myds->DSS = STATE_QUERY_SENT_NET;
				unsigned int nTrx = NumActiveTransactions();
				const char txn_state = (nTrx ? 'T' : 'I');
				client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, txn_state, NULL, {});

				if (mirror == false) {
					RequestEnd(NULL);
				}
				else {
					client_myds->DSS = STATE_SLEEP;
					status = WAITING_CLIENT_DATA;
				}
				l_free(pkt->size, pkt->ptr);
				return true;
			} 
			// send other DISCARD variants to Backend
		} else if (strncasecmp(dig, "DEALLOCATE ", 11) == 0) {
#ifdef DEBUG
			{
				std::string nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing DEALLOCATE command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig, ';') && (index(dig, ';') != dig + strlen(dig) - 1)) {
				string nqn;
				if (pgsql_thread___parse_failure_logs_digest)
					nqn = string(CurrentQuery.get_digest_text());
				else
					nqn = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				proxy_warning(
					"Unable to parse multi-statements command with DEALLOCATE statement from client"
					" %s:%d: setting lock hostgroup. Command: %s\n", client_myds->addr.addr,
					client_myds->addr.port, nqn.c_str()
				);
				*lock_hostgroup = true;
				return false;
			}

			std::string nq = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);

			RE2::GlobalReplace(&nq, "(?U)/\\*.*\\*/", "");
			RE2::GlobalReplace(&nq, "(?i)\\bDEALLOCATE\\b(\\s+PREPARE)?", "");
			RE2::GlobalReplace(&nq, "[^\\w]*", "");

			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Parsing DEALLOCATE command %s\n", nq.c_str());
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing DEALLOCATE command = %s\n", nq.c_str());

			const char* dealloc_value = nq.c_str();
			if (strncasecmp(dealloc_value, "ALL", 3) == 0) {
				client_myds->myconn->local_stmts->client_close_all();
			} else {
				client_myds->myconn->local_stmts->client_close(dealloc_value);
			}
			client_myds->DSS = STATE_QUERY_SENT_NET;
			unsigned int nTrx = NumActiveTransactions();
			const char txn_state = (nTrx ? 'T' : 'I');
			client_myds->myprot.generate_ok_packet(true, true, NULL, 0, dig, txn_state, NULL, {});

			if (mirror == false) {
				RequestEnd(NULL);
			} else {
				client_myds->DSS = STATE_SLEEP;
				status = WAITING_CLIENT_DATA;
			}
			l_free(pkt->size, pkt->ptr);
			return true;
		}
	}

	if (mirror == true) { // for mirror session we exit here
		current_hostgroup = qpo->destination_hostgroup;
		return false;
	}

#if 0	
	// handle case #1797
	// handle case #2564
	if ((pkt->size == SELECT_CONNECTION_ID_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncasecmp((char*)SELECT_CONNECTION_ID, (char*)pkt->ptr + 5, pkt->size - 5) == 0)) {
		char buf[32];
		char buf2[32];
		sprintf(buf, "%u", thread_session_id);
		int l0 = strlen("CONNECTION_ID()");
		memcpy(buf2, (char*)pkt->ptr + 5 + SELECT_CONNECTION_ID_LEN - l0, l0);
		buf2[l0] = 0;
		unsigned int nTrx = NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		PgSQL_Data_Stream* myds = client_myds;
		MySQL_Protocol* myprot = &client_myds->myprot;
		myds->DSS = STATE_QUERY_SENT_DS;
		int sid = 1;
		myprot->generate_pkt_column_count(true, NULL, NULL, sid, 1); sid++;
		myprot->generate_pkt_field(true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", buf2, (char*)"", 63, 31, MYSQL_TYPE_LONGLONG, 161, 0, false, 0, NULL); sid++;
		myds->DSS = STATE_COLUMN_DEFINITION;

		bool deprecate_eof_active = myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		if (!deprecate_eof_active) {
			myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
		}

		char** p = (char**)malloc(sizeof(char*) * 1);
		unsigned long* l = (unsigned long*)malloc(sizeof(unsigned long*) * 1);
		l[0] = strlen(buf);
		p[0] = buf;
		myprot->generate_pkt_row(true, NULL, NULL, sid, 1, l, p); sid++;
		myds->DSS = STATE_ROW;

		if (deprecate_eof_active) {
			myprot->generate_pkt_OK(true, NULL, NULL, sid, 0, 0, setStatus, 0, NULL, true); sid++;
		}
		else {
			myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
		}
		myds->DSS = STATE_SLEEP;
		RequestEnd(NULL);
		l_free(pkt->size, pkt->ptr);
		free(p);
		free(l);
		return true;
	}

	// handle case #1421 , about LAST_INSERT_ID
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char* dig = CurrentQuery.QueryParserArgs.digest_text;
		if (strcasestr(dig, "LAST_INSERT_ID") || strcasestr(dig, "@@IDENTITY")) {
			// we need to try to execute it where the last write was successful
			if (last_HG_affected_rows >= 0) {
				PgSQL_Backend* _mybe = NULL;
				_mybe = find_backend(last_HG_affected_rows);
				if (_mybe) {
					if (_mybe->server_myds) {
						if (_mybe->server_myds->myconn) {
							if (_mybe->server_myds->myconn->pgsql_conn) { // we have an established connection
								// this seems to be the right backend
								qpo->destination_hostgroup = last_HG_affected_rows;
								current_hostgroup = qpo->destination_hostgroup;
								return false; // execute it on backend!
							}
						}
					}
				}
			}

			// if we reached here, we don't know the right backend
			// we try to determine if it is a simple "SELECT LAST_INSERT_ID()" or "SELECT @@IDENTITY" and we return pgsql->last_insert_id

			//handle 2564
			if (
				(pkt->size == SELECT_LAST_INSERT_ID_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncasecmp((char*)SELECT_LAST_INSERT_ID, (char*)pkt->ptr + 5, pkt->size - 5) == 0)
				||
				(pkt->size == SELECT_LAST_INSERT_ID_LIMIT1_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncasecmp((char*)SELECT_LAST_INSERT_ID_LIMIT1, (char*)pkt->ptr + 5, pkt->size - 5) == 0)
				||
				(pkt->size == SELECT_VARIABLE_IDENTITY_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncasecmp((char*)SELECT_VARIABLE_IDENTITY, (char*)pkt->ptr + 5, pkt->size - 5) == 0)
				||
				(pkt->size == SELECT_VARIABLE_IDENTITY_LIMIT1_LEN + 5 && *((char*)(pkt->ptr) + 4) == (char)0x03 && strncasecmp((char*)SELECT_VARIABLE_IDENTITY_LIMIT1, (char*)pkt->ptr + 5, pkt->size - 5) == 0)
				) {
				char buf[32];
				sprintf(buf, "%llu", last_insert_id);
				char buf2[32];
				int l0 = 0;
				if (strcasestr(dig, "LAST_INSERT_ID")) {
					l0 = strlen("LAST_INSERT_ID()");
					memcpy(buf2, (char*)pkt->ptr + 5 + SELECT_LAST_INSERT_ID_LEN - l0, l0);
				}
				else if (strcasestr(dig, "@@IDENTITY")) {
					l0 = strlen("@@IDENTITY");
					memcpy(buf2, (char*)pkt->ptr + 5 + SELECT_VARIABLE_IDENTITY_LEN - l0, l0);
				}
				buf2[l0] = 0;
				unsigned int nTrx = NumActiveTransactions();
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				PgSQL_Data_Stream* myds = client_myds;
				MySQL_Protocol* myprot = &client_myds->myprot;
				myds->DSS = STATE_QUERY_SENT_DS;
				int sid = 1;
				myprot->generate_pkt_column_count(true, NULL, NULL, sid, 1); sid++;
				myprot->generate_pkt_field(true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", buf2, (char*)"", 63, 31, MYSQL_TYPE_LONGLONG, 161, 0, false, 0, NULL); sid++;
				myds->DSS = STATE_COLUMN_DEFINITION;

				bool deprecate_eof_active = myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
				if (!deprecate_eof_active) {
					myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
				}
				char** p = (char**)malloc(sizeof(char*) * 1);
				unsigned long* l = (unsigned long*)malloc(sizeof(unsigned long*) * 1);
				l[0] = strlen(buf);
				p[0] = buf;
				myprot->generate_pkt_row(true, NULL, NULL, sid, 1, l, p); sid++;
				myds->DSS = STATE_ROW;
				if (deprecate_eof_active) {
					myprot->generate_pkt_OK(true, NULL, NULL, sid, 0, 0, setStatus, 0, NULL, true); sid++;
				}
				else {
					myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
				}
				myds->DSS = STATE_SLEEP;
				RequestEnd(NULL);
				l_free(pkt->size, pkt->ptr);
				free(p);
				free(l);
				return true;
			}

			// if we reached here, we don't know the right backend and we cannot answer the query directly
			// We continue the normal way

			// as a precaution, we reset cache_ttl
			qpo->cache_ttl = 0;
		}
	}
#endif

	// handle command KILL #860
	//if (prepared == false) {
	if (handle_command_query_kill(pkt)) {
		return true;
	}
	//}
	if (qpo->cache_ttl > 0 && ((stmt_type & PGSQL_EXTENDED_QUERY_TYPE_EXECUTE) == 0)) {
		
		const std::shared_ptr<PgSQL_QC_entry_t> pgsql_qc_entry = GloPgQC->get(
			client_myds->myconn->userinfo->hash,
			(const unsigned char*)CurrentQuery.QueryPointer,
			CurrentQuery.QueryLength,
			thread->curtime / 1000,
			qpo->cache_ttl
		);
		if (pgsql_qc_entry) {
			// FIXME: Add Error Transaction state detection
			unsigned int nTrx = NumActiveTransactions();
			PgSQL_Data_Stream::copy_buffer_to_resultset(client_myds->PSarrayOUT, 
				pgsql_qc_entry->value, pgsql_qc_entry->length, (nTrx ? 'T' : 'I'));
			//client_myds->PSarrayOUT->copy_add(resultset, 0, resultset->len);
			if (transaction_persistent_hostgroup == -1) {
				// not active, we can change it
				current_hostgroup = -1;
			}
			RequestEnd(NULL);
			l_free(pkt->size, pkt->ptr);
			return true;
		}
	}

__exit_set_destination_hostgroup:

	if (qpo->next_query_flagIN >= 0) {
		next_query_flagIN = qpo->next_query_flagIN;
	}
	if (qpo->destination_hostgroup >= 0) {
		if (transaction_persistent_hostgroup == -1) {
			current_hostgroup = qpo->destination_hostgroup;
		}
	}

	if (pgsql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
		if (locked_on_hostgroup >= 0) {
			if (current_hostgroup != locked_on_hostgroup) {
				client_myds->DSS = STATE_QUERY_SENT_NET;
				char buf[140];
				sprintf(buf, "ProxySQL Error: connection is locked to hostgroup %d but trying to reach hostgroup %d", locked_on_hostgroup, current_hostgroup);
				client_myds->myprot.generate_error_packet(true, true, buf,
					PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, false);
				thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
				RequestEnd(NULL);
				l_free(pkt->size, pkt->ptr);
				return true;
			}
		}
	}
	return false;
}

#if 0
void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t* pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_STATISTICS packet\n");
	l_free(pkt->size, pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_statistics_response(true, NULL, NULL);
	client_myds->DSS = STATE_SLEEP;
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t* pkt, bool* wrong_pass) {
	
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_CHANGE_USER packet\n");
	//if (session_type == PROXYSQL_SESSION_PGSQL) {
	if (session_type == PROXYSQL_SESSION_PGSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		reset();
		init();
		if (client_authenticated) {
			if (use_ldap_auth == false) {
				GloPgAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
			}
			else {
				GloMyLdapAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->fe_username);
			}
		}
		client_authenticated = false;
		if (client_myds->myprot.process_pkt_COM_CHANGE_USER((unsigned char*)pkt->ptr, pkt->size) == true) {
			l_free(pkt->size, pkt->ptr);
			client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, 2, 0, NULL);
			client_myds->DSS = STATE_SLEEP;
			status = WAITING_CLIENT_DATA;
			*wrong_pass = false;
			client_authenticated = true;
			//int free_users=0;
			int used_users = 0;
			/*free_users */GloPgAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
			// FIXME: max_connections is not handled for CHANGE_USER
		}
		else {
			l_free(pkt->size, pkt->ptr);
			// 'COM_CHANGE_USER' didn't supply a password, and an 'Auth Switch Response' is
			// required, going back to 'STATE_SERVER_HANDSHAKE' to perform the regular
			// 'Auth Switch Response' for a connection is required. See #3504 for more context.
			if (change_user_auth_switch) {
				client_myds->DSS = STATE_SERVER_HANDSHAKE;
				status = CONNECTING_CLIENT;
				return;
			}

			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Wrong credentials for frontend: disconnecting\n");
			*wrong_pass = true;
			// FIXME: this should become close connection
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			char* client_addr = NULL;
			if (client_myds->client_addr) {
				char buf[512];
				switch (client_myds->client_addr->sa_family) {
				case AF_INET: {
					struct sockaddr_in* ipv4 = (struct sockaddr_in*)client_myds->client_addr;
					inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
					client_addr = strdup(buf);
					break;
				}
				case AF_INET6: {
					struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)client_myds->client_addr;
					inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
					client_addr = strdup(buf);
					break;
				}
				default:
					client_addr = strdup((char*)"localhost");
					break;
				}
			}
			else {
				client_addr = strdup((char*)"");
			}
			char* _s = (char*)malloc(strlen(client_myds->myconn->userinfo->username) + 100 + strlen(client_addr));
			sprintf(_s, "ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			proxy_error("ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)\n", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 2, 1045, (char*)"28000", _s, true);
			free(_s);
			__sync_fetch_and_add(&PgHGM->status.access_denied_wrong_password, 1);
		}
	}
	else {
		//FIXME: send an error message saying "not supported" or disconnect
		l_free(pkt->size, pkt->ptr);
	}
}

void PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(PtrSize_t* pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got MYSQL_COM_RESET_CONNECTION packet\n");

	if (session_type == PROXYSQL_SESSION_PGSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		// Backup the current relevant session values
		int default_hostgroup = this->default_hostgroup;
		bool transaction_persistent = this->transaction_persistent;

		// Re-initialize the session
		reset();
		init();

		// Recover the relevant session values
		this->default_hostgroup = default_hostgroup;
		this->transaction_persistent = transaction_persistent;
		//-- client_myds->myconn->set_charset(default_charset, NAMES);

		if (user_attributes != NULL && strlen(user_attributes)) {
			nlohmann::json j_user_attributes = nlohmann::json::parse(user_attributes);
			auto default_transaction_isolation = j_user_attributes.find("default-transaction_isolation");

			if (default_transaction_isolation != j_user_attributes.end()) {
				std::string def_trx_isolation_val =
					j_user_attributes["default-transaction_isolation"].get<std::string>();
				pgsql_variables.client_set_value(this, SQL_ISOLATION_LEVEL, def_trx_isolation_val.c_str());
			}
		}

		l_free(pkt->size, pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, 2, 0, NULL);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
	}
	else {
		l_free(pkt->size, pkt->ptr);

		std::string t_sql_error_msg{ "Received unsupported 'COM_RESET_CONNECTION' for session type '%s'" };
		std::string sql_error_msg{};
		string_format(t_sql_error_msg, sql_error_msg, proxysql_session_type_str(session_type).c_str());

		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 2, 1047, (char*)"28000", sql_error_msg.c_str(), true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
	}
}
#endif
void PgSQL_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection() {
	// Get a MySQL Connection

	PgSQL_Connection* mc = NULL;
	char uuid[64];
	uint64_t trxid = 0;
	unsigned long long now_us = 0;
	if (qpo->max_lag_ms >= 0) {
		if (qpo->max_lag_ms > 360000) { // this is an absolute time, we convert it to relative
			if (now_us == 0) {
				now_us = realtime_time();
			}
			long long now_ms = now_us / 1000;
			qpo->max_lag_ms = now_ms - qpo->max_lag_ms;
			if (qpo->max_lag_ms < 0) {
				qpo->max_lag_ms = -1; // time expired
			}
		}
	}
	if (session_fast_forward == SESSION_FORWARD_TYPE_NONE && qpo->create_new_conn == false) {
#ifndef STRESSTEST_POOL
		mc = thread->get_MyConn_local(mybe->hostgroup_id, this, NULL, 0, (int)qpo->max_lag_ms);
#endif // STRESSTEST_POOL
	}
#ifdef STRESSTEST_POOL
	// Check STRESSTEST_POOL in MySQL_HostGroups_Manager.h
	// Note: this works only if session_fast_forward==false and create_new_conn is false too
#define NUM_SLOW_LOOPS 1000
		// if STRESSTESTPOOL_MEASURE is define, time is measured in Query_Processor_time_nsec
		// even if not the right variable
//#define STRESSTESTPOOL_MEASURE
#ifdef STRESSTESTPOOL_MEASURE
	timespec begint;
	timespec endt;
	clock_gettime(CLOCK_MONOTONIC, &begint);
#endif // STRESSTESTPOOL_MEASURE
	for (unsigned int loops = 0; loops < NUM_SLOW_LOOPS; loops++) {
#endif // STRESSTEST_POOL

		if (mc == NULL) {
			if (trxid) {
				mc = PgHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, (session_fast_forward || qpo->create_new_conn), uuid, trxid, -1);
			}
			else {
				mc = PgHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, (session_fast_forward || qpo->create_new_conn), NULL, 0, (int)qpo->max_lag_ms);
			}
#ifdef STRESSTEST_POOL
			if (mc && (loops < NUM_SLOW_LOOPS - 1)) {
				if (mc->pgsql) {
					mybe->server_myds->attach_connection(mc);
					mybe->server_myds->DSS = STATE_NOT_INITIALIZED;
					mybe->server_myds->return_MySQL_Connection_To_Pool();
					mc = NULL;
				}
			}
#endif // STRESSTEST_POOL
		}
		else {
			thread->status_variables.stvar[st_var_ConnPool_get_conn_immediate]++;
		}
#ifdef STRESSTEST_POOL
#ifdef STRESSTESTPOOL_MEASURE
		clock_gettime(CLOCK_MONOTONIC, &endt);
		thread->status_variables.query_processor_time = thread->status_variables.query_processor_time +
			(endt.tv_sec * 1000000000 + endt.tv_nsec) -
			(begint.tv_sec * 1000000000 + begint.tv_nsec);
#endif // STRESSTESTPOOL_MEASURE
	}
#endif // STRESSTEST_POOL
	if (mc) {
		mybe->server_myds->attach_connection(mc);
		thread->status_variables.stvar[st_var_ConnPool_get_conn_success]++;
	}
	else {
		thread->status_variables.stvar[st_var_ConnPool_get_conn_failure]++;
	}
	if (qpo->max_lag_ms >= 0) {
		if (qpo->max_lag_ms <= 360000) { // this is a relative time , we convert it to absolute
			if (mc == NULL) {
				if (CurrentQuery.waiting_since == 0) {
					CurrentQuery.waiting_since = thread->curtime;
					thread->status_variables.stvar[st_var_queries_with_max_lag_ms__delayed]++;
				}
			}
			if (now_us == 0) {
				now_us = realtime_time();
			}
			long long now_ms = now_us / 1000;
			qpo->max_lag_ms = now_ms - qpo->max_lag_ms;
		}
	}
	if (mc) {
		if (CurrentQuery.waiting_since) {
			unsigned long long waited = thread->curtime - CurrentQuery.waiting_since;
			thread->status_variables.stvar[st_var_queries_with_max_lag_ms__total_wait_time_us] += waited;
			CurrentQuery.waiting_since = 0;
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- server_myds=%p -- PgSQL_Connection %p\n", this, mybe->server_myds, mybe->server_myds->myconn);
	if (mybe->server_myds->myconn == NULL) {
		// we couldn't get a connection for whatever reason, ex: no backends, or too busy
		if (thread->mypolls.poll_timeout == 0) { // tune poll timeout
			thread->mypolls.poll_timeout = pgsql_thread___poll_timeout_on_failure * 1000;
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%u\n", mybe->server_myds->sess, mybe->server_myds, thread->mypolls.poll_timeout);
		}
		else {
			if (thread->mypolls.poll_timeout > (unsigned int)pgsql_thread___poll_timeout_on_failure * 1000) {
				thread->mypolls.poll_timeout = pgsql_thread___poll_timeout_on_failure * 1000;
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%u\n", mybe->server_myds->sess, mybe->server_myds, thread->mypolls.poll_timeout);
			}
		}
		return;
	}
	if (mybe->server_myds->myconn->fd == -1) {
		// we didn't get a valid connection, we need to create one
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- PgSQL Connection has no FD\n", this);
		PgSQL_Connection* myconn = mybe->server_myds->myconn;
		myconn->userinfo->set(client_myds->myconn->userinfo);

		myconn->handler(0);
		mybe->server_myds->fd = myconn->fd;
		mybe->server_myds->DSS = STATE_MARIADB_CONNECTING;
		status = CONNECTING_SERVER;
		mybe->server_myds->myconn->reusable = true;
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- PgSQL Connection found = %p\n", this, mybe->server_myds->myconn);
		mybe->server_myds->assign_fd_from_pgsql_conn();
		mybe->server_myds->myds_type = MYDS_BACKEND;
		mybe->server_myds->DSS = STATE_READY;

		if (session_fast_forward) {
			status = FAST_FORWARD;
			mybe->server_myds->myconn->reusable = false; // the connection cannot be usable anymore
		}
	}
}

void PgSQL_Session::PgSQL_Result_to_PgSQL_wire(PgSQL_Connection* _conn, PgSQL_Data_Stream* _myds) {
	if (_conn == NULL) {
		// error
		client_myds->myprot.generate_error_packet(true, true, "Lost connection to PostgreSQL server during query", 
			PGSQL_ERROR_CODES::ERRCODE_CONNECTION_FAILURE, false);
		return;
	}

	PgSQL_Query_Result* query_result = _conn->query_result;

	if (query_result && query_result->get_result_packet_type() != PGSQL_QUERY_RESULT_NO_DATA) {
		bool transfer_started = query_result->is_transfer_started();
		// if there is an error, it will be false so results are not cached
		bool is_tuple = (
			(query_result->get_result_packet_type() == (PGSQL_QUERY_RESULT_TUPLE | PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_READY)) ||
			(query_result->get_result_packet_type() == (PGSQL_QUERY_RESULT_NOTICE | PGSQL_QUERY_RESULT_TUPLE | PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_READY))
			);
		const uint64_t num_rows  = query_result->get_num_rows();
		const uint64_t resultset_size = query_result->get_resultset_size();
		const auto _affected_rows = query_result->get_affected_rows();
		if (_affected_rows != static_cast<unsigned long long>(-1)) {
			 CurrentQuery.affected_rows = _affected_rows;
			 CurrentQuery.have_affected_rows = true;
		}
		CurrentQuery.rows_sent = num_rows;
		bool resultset_completed = query_result->get_resultset(client_myds->PSarrayOUT);
		if (_conn->processing_multi_statement == false && status != PROCESSING_STMT_EXECUTE)
			assert(resultset_completed); // the resultset should always be completed if PgSQL_Result_to_PgSQL_wire is called
		if (transfer_started == false && _conn->processing_multi_statement == false && 
			status != PROCESSING_STMT_EXECUTE) { // we have all the resultset when PgSQL_Result_to_PgSQL_wire was called
			if (qpo && qpo->cache_ttl > 0 && is_tuple == true) { // the resultset should be cached
				
				if (_conn->is_error_present() == false &&
					(/* check warnings count here*/ true || 
						pgsql_thread___query_cache_handle_warnings == 1)) { // no errors

					if (
						(qpo->cache_empty_result == 1) || 
							(
								(qpo->cache_empty_result == -1) &&
								(thread->variables.query_cache_stores_empty_result || num_rows)
							)
						) {
						// Query Cache will have the ownership to buff. No need to free it here
						unsigned char* buff = PgSQL_Data_Stream::copy_array_to_buffer(client_myds->PSarrayOUT, 
							resultset_size, false);
						GloPgQC->set(
							client_myds->myconn->userinfo->hash,
							CurrentQuery.QueryPointer,
							CurrentQuery.QueryLength,
							buff, 
							resultset_size,
							thread->curtime / 1000,
							thread->curtime / 1000,
							thread->curtime / 1000 + qpo->cache_ttl
						);
					}
				}
			}
		}
	} else { // if query result is empty, means there was an error before query result was generated

		if (!_conn->is_error_present())
			assert(0); // if query result is empty, there should be an error present in connection.

		if (_myds && _myds->killed_at) { 
			if (_myds->kill_type == 0) {
				client_myds->myprot.generate_error_packet(true, true, (char*)"Query execution was interrupted, query_timeout exceeded",
					PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED, false);
				//PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, _conn->parent->myhgc->hid, _conn->parent->address, _conn->parent->port, 1907);
			}
			else {
				client_myds->myprot.generate_error_packet(true, true, (char*)"Query execution was interrupted",
					PGSQL_ERROR_CODES::ERRCODE_QUERY_CANCELED, false);
				//PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, _conn->parent->myhgc->hid, _conn->parent->address, _conn->parent->port, 1317);
			}
		}
		else {
			client_myds->myprot.generate_error_packet(true, true, _conn->get_error_message().c_str(), _conn->get_error_code(), false);
			//PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::proxysql, _conn->parent->myhgc->hid, _conn->parent->address, _conn->parent->port, 1907);
		}

		/*int myerrno = mysql_errno(pgsql);
		if (myerrno == 0) {
			unsigned int num_rows = mysql_affected_rows(pgsql);
			uint16_t setStatus = (active_transactions ? SERVER_STATUS_IN_TRANS : 0);
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			if (pgsql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus |= SERVER_MORE_RESULTS_EXIST;
			setStatus |= (pgsql->server_status & ~SERVER_STATUS_AUTOCOMMIT); // get flags from server_status but ignore autocommit
			setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
			client_myds->myprot.generate_pkt_OK(true, NULL, NULL, client_myds->pkt_sid + 1, num_rows, pgsql->insert_id, setStatus, warning_count, pgsql->info);
			//client_myds->pkt_sid++;
		}
		else {
			// error
			char sqlstate[10];
			sprintf(sqlstate, "%s", mysql_sqlstate(pgsql));
			if (_myds && _myds->killed_at) { // see case #750
				if (_myds->kill_type == 0) {
					client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, client_myds->pkt_sid + 1, 1907, sqlstate, (char*)"Query execution was interrupted, query_timeout exceeded");
				}
				else {
					client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, client_myds->pkt_sid + 1, 1317, sqlstate, (char*)"Query execution was interrupted");
				}
			}
			else {
				client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, client_myds->pkt_sid + 1, mysql_errno(pgsql), sqlstate, mysql_error(pgsql));
			}
			//client_myds->pkt_sid++;
		}
		*/
	}
}

void PgSQL_Session::SQLite3_to_MySQL(SQLite3_result* result, char* error, int affected_rows, MySQL_Protocol* myprot, bool in_transaction, bool deprecate_eof_active) {
	assert(myprot);
	MySQL_Data_Stream* myds = myprot->get_myds();
	myds->DSS = STATE_QUERY_SENT_DS;
	int sid = 1;
	if (result) {
		myprot->generate_pkt_column_count(true, NULL, NULL, sid, result->columns); sid++;
		for (int i = 0; i < result->columns; i++) {
			myprot->generate_pkt_field(true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", result->column_definition[i]->name, (char*)"", 33, 15, MYSQL_TYPE_VAR_STRING, 1, 0x1f, false, 0, NULL);
			sid++;
		}
		myds->DSS = STATE_COLUMN_DEFINITION;
		unsigned int nTrx = 0;
		uint16_t setStatus = 0;
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		if (in_transaction == false) {
			nTrx = NumActiveTransactions();
			setStatus |= (nTrx ? SERVER_STATUS_IN_TRANS : 0);
		}
		else {
			// this is for SQLite3 Server
			if (session_type == PROXYSQL_SESSION_SQLITE) {
				//if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			}
			else {
				// for sessions that are not SQLITE . Admin and Clickhouse .
				// default
				setStatus |= SERVER_STATUS_AUTOCOMMIT;
			}
			setStatus |= SERVER_STATUS_IN_TRANS;
		}
		if (!deprecate_eof_active) {
			myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
		}

		char** p = (char**)malloc(sizeof(char*) * result->columns);
		unsigned long* l = (unsigned long*)malloc(sizeof(unsigned long*) * result->columns);

		MySQL_ResultSet query_result{};
		query_result.buffer_init(myprot);

		for (int r = 0; r < result->rows_count; r++) {
			for (int i = 0; i < result->columns; i++) {
				l[i] = result->rows[r]->sizes[i];
				p[i] = result->rows[r]->fields[i];
			}
			sid = myprot->generate_pkt_row3(&query_result, NULL, sid, result->columns, l, p, 0); sid++;
		}

		query_result.buffer_to_PSarrayOut();
		query_result.get_resultset(myds->PSarrayOUT);

		myds->DSS = STATE_ROW;

		if (deprecate_eof_active) {
			myprot->generate_pkt_OK(true, NULL, NULL, sid, 0, 0, setStatus, 0, NULL, true); sid++;
		}
		else {
			myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus); sid++;
		}

		myds->DSS = STATE_SLEEP;
		free(l);
		free(p);

	}
	else { // no result set
		if (error) {
			// there was an error
			if (strcmp(error, (char*)"database is locked") == 0) {
				client_myds->myprot.generate_error_packet(true, true, error,
					PGSQL_ERROR_CODES::ERRCODE_T_R_DEADLOCK_DETECTED, false);
			}
			else {
				client_myds->myprot.generate_error_packet(true, true, error,
					PGSQL_ERROR_CODES::ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION, false);
			}
		}
		else {
			// no error, DML succeeded
			unsigned int nTrx = 0;
			uint16_t setStatus = 0;
			if (in_transaction == false) {
				nTrx = NumActiveTransactions();
				setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			}
			else {
				// this is for SQLite3 Server
				if (session_type == PROXYSQL_SESSION_SQLITE) {
					//if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				}
				else {
					// for sessions that are not SQLITE . Admin and Clickhouse .
					// default
					setStatus |= SERVER_STATUS_AUTOCOMMIT;
				}
				setStatus |= SERVER_STATUS_IN_TRANS;
			}
			myprot->generate_pkt_OK(true, NULL, NULL, sid, affected_rows, 0, setStatus, 0, NULL);
		}
		myds->DSS = STATE_SLEEP;
	}
}

unsigned long long PgSQL_Session::IdleTime() {
	unsigned long long ret = 0;
	if (client_myds == 0) return 0;
	if (status != WAITING_CLIENT_DATA && status != CONNECTING_CLIENT) return 0;
	int idx = client_myds->poll_fds_idx;
	unsigned long long last_sent = thread->mypolls.last_sent[idx];
	unsigned long long last_recv = thread->mypolls.last_recv[idx];
	unsigned long long last_time = (last_sent > last_recv ? last_sent : last_recv);
	if (thread->curtime > last_time) {
		ret = thread->curtime - last_time;
	}
	return ret;
}



// this is called either from RequestEnd(), or at the end of executing
// prepared statements
void PgSQL_Session::LogQuery(PgSQL_Data_Stream* myds) {
	// we need to access statistics before calling CurrentQuery.end()
	// so we track the time here
	CurrentQuery.end_time = thread->curtime;

	if (qpo) {
		if (qpo->log == 1) {
			GloPgSQL_Logger->log_request(this, myds);	// we send for logging only if logging is enabled for this query
		}
		else {
			if (qpo->log == -1) {
				if (pgsql_thread___eventslog_default_log == 1) {
					GloPgSQL_Logger->log_request(this, myds);	// we send for logging only if enabled by default
				}
			}
		}
	}
}
void PgSQL_Session::RequestEnd(PgSQL_Data_Stream* myds, const unsigned int myerrno, const char * errmsg) {
	// check if multiplexing needs to be disabled
	char* qdt = NULL;

	if (status != PROCESSING_STMT_EXECUTE && 
		status != PROCESSING_STMT_DESCRIBE) {
		qdt = CurrentQuery.get_digest_text();
	} else {
		qdt = CurrentQuery.extended_query_info.stmt_info->digest_text;
	}

	if (qdt) {
		// is savepoint currently present in transaction.
		int savepoint_count = -1; // haven't checked yet

		// we do not maintain the transaction variable state if the session is locked on a hostgroup 
		// or is a Fast Forward session.
		if (locked_on_hostgroup == -1 && session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
			transaction_state_manager->handle_transaction(qdt);
			savepoint_count = transaction_state_manager->get_savepoint_count();
		}

		if (myds && myds->myconn) {
			myds->myconn->ProcessQueryAndSetStatusFlags(qdt, savepoint_count);
		}
	}

	if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
		LogQuery(myds);
	}

	GloPgQPro->delete_QP_out(qpo);
	// if there is an associated myds, clean its status
	if (myds) {
		// if there is a pgsql connection, clean its status
		if (myds->myconn) {
			myds->myconn->async_free_result();
			myds->myconn->compute_unknown_transaction_status();
		}
		myds->free_pgsql_real_query();
	}
	if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) {
		// reset status of the session
		status = WAITING_CLIENT_DATA;
		if (client_myds) {
			// reset status of client data stream
			client_myds->DSS = STATE_SLEEP;
			// finalize the query
			CurrentQuery.end();
		}
	}
	//started_sending_data_to_client = false;
	previous_hostgroup = current_hostgroup;
}

// this function tries to report all the memory statistics related to the sessions
void PgSQL_Session::Memory_Stats() {
	if (thread == NULL)
		return;
	unsigned int i;
	unsigned long long backend = 0;
	unsigned long long frontend = 0;
	unsigned long long internal = 0;
	internal += sizeof(PgSQL_Session);
	if (qpo)
		internal += sizeof(PgSQL_Query_Processor_Output);
	if (client_myds) {
		internal += sizeof(PgSQL_Data_Stream);
		if (client_myds->queueIN.buffer)
			frontend += QUEUE_T_DEFAULT_SIZE;
		if (client_myds->queueOUT.buffer)
			frontend += QUEUE_T_DEFAULT_SIZE;
		if (client_myds->myconn) {
			internal += sizeof(PgSQL_Connection);
		}
		if (client_myds->PSarrayIN) {
			internal += client_myds->PSarrayIN->total_size();
		}
		if (client_myds->PSarrayIN) {
			if (session_fast_forward) {
				internal += client_myds->PSarrayOUT->total_size();
			} else {
				internal += client_myds->PSarrayOUT->total_size(PGSQL_RESULTSET_BUFLEN);
				//internal += client_myds->resultset->total_size(PGSQL_RESULTSET_BUFLEN);
			}
		}
	}
	for (i = 0; i < mybes->len; i++) {
		PgSQL_Backend* _mybe = (PgSQL_Backend*)mybes->index(i);
		internal += sizeof(PgSQL_Backend);
		if (_mybe->server_myds) {
			internal += sizeof(PgSQL_Data_Stream);
			if (_mybe->server_myds->queueIN.buffer)
				backend += QUEUE_T_DEFAULT_SIZE;
			if (_mybe->server_myds->queueOUT.buffer)
				backend += QUEUE_T_DEFAULT_SIZE;
			if (_mybe->server_myds->myconn) {
				PgSQL_Connection* myconn = _mybe->server_myds->myconn;
				internal += sizeof(PgSQL_Connection);
				if (myconn->is_connected()) {
					//backend += sizeof(MYSQL);
					//backend += myconn->pgsql->net.max_packet;
					backend += myconn->get_memory_usage();
					//backend += (4096 * 15); // ASYNC_CONTEXT_DEFAULT_STACK_SIZE
				}
				if (myconn->query_result) {
					backend += myconn->query_result->current_size();
				}
			}
		}
	}
	thread->status_variables.stvar[st_var_mysql_backend_buffers_bytes] += backend;
	thread->status_variables.stvar[st_var_mysql_frontend_buffers_bytes] += frontend;
	thread->status_variables.stvar[st_var_mysql_session_internal_bytes] += internal;
}


void PgSQL_Session::create_new_session_and_reset_connection(PgSQL_Data_Stream* _myds) {
	PgSQL_Data_Stream* new_myds = NULL;
	PgSQL_Connection* mc = _myds->myconn;
	// we remove the connection from the original data stream
	_myds->detach_connection();
	_myds->unplug_backend();

	// we create a brand new session, a new data stream, and attach the connection to it
	PgSQL_Session* new_sess = new PgSQL_Session();
	new_sess->mybe = new_sess->find_or_create_backend(mc->parent->myhgc->hid);

	new_myds = new_sess->mybe->server_myds;
	new_myds->attach_connection(mc);
	new_myds->assign_fd_from_pgsql_conn();
	new_myds->myds_type = MYDS_BACKEND;
	new_sess->to_process = 1;
	new_myds->wait_until = thread->curtime + pgsql_thread___connect_timeout_server * 1000;   // max_timeout
	mc->last_time_used = thread->curtime;
	new_myds->myprot.init(&new_myds, new_myds->myconn->userinfo, NULL);
	new_sess->status = RESETTING_CONNECTION;
	mc->async_state_machine = ASYNC_IDLE; // may not be true, but is used to correctly perform error handling
	mc->auto_increment_delay_token = 0;
	new_myds->DSS = STATE_MARIADB_QUERY;
	thread->register_session_connection_handler(new_sess, true);
	if (new_myds->mypolls == NULL) {
		thread->mypolls.add(POLLIN | POLLOUT, new_myds->fd, new_myds, thread->curtime);
	}
	int rc = new_sess->handler();
	if (rc == -1) {
		unsigned int sess_idx = thread->mysql_sessions->len - 1;
		thread->unregister_session(sess_idx);
		delete new_sess;
	}
}

bool PgSQL_Session::handle_command_query_kill(PtrSize_t* pkt) {
	/*unsigned char command_type = *((unsigned char*)pkt->ptr + sizeof(mysql_hdr));
	if (CurrentQuery.QueryParserArgs.digest_text) {
		if (command_type == _MYSQL_COM_QUERY) {
			if (client_myds && client_myds->myconn) {
				PgSQL_Connection* mc = client_myds->myconn;
				if (mc->userinfo && mc->userinfo->username) {
					if (CurrentQuery.PgQueryCmd == PGSQL_QUERY_KILL) {
						char* qu = query_strip_comments((char*)pkt->ptr + 1 + sizeof(mysql_hdr), pkt->size - 1 - sizeof(mysql_hdr), 
							pgsql_thread___query_digests_lowercase);
						string nq = string(qu, strlen(qu));
						re2::RE2::Options* opt2 = new re2::RE2::Options(RE2::Quiet);
						opt2->set_case_sensitive(false);
						char* pattern = (char*)"^KILL\\s+(CONNECTION |QUERY |)\\s*(\\d+)\\s*$";
						re2::RE2* re = new RE2(pattern, *opt2);
						int id = 0;
						string tk;
						RE2::FullMatch(nq, *re, &tk, &id);
						delete re;
						delete opt2;
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 2, "filtered query= \"%s\"\n", qu);
						free(qu);
						if (id) {
							int tki = -1;
							if (tk.c_str()) {
								if ((strlen(tk.c_str()) == 0) || (strcasecmp(tk.c_str(), "CONNECTION ") == 0)) {
									tki = 0;
								}
								else {
									if (strcasecmp(tk.c_str(), "QUERY ") == 0) {
										tki = 1;
									}
								}
							}
							if (tki >= 0) {
								proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 2, "Killing %s %d\n", (tki == 0 ? "CONNECTION" : "QUERY"), id);
								GloPTH->kill_connection_or_query(id, (tki == 0 ? false : true), mc->userinfo->username);
								client_myds->DSS = STATE_QUERY_SENT_NET;
								unsigned int nTrx = NumActiveTransactions();
								uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0);
								if (autocommit) setStatus = SERVER_STATUS_AUTOCOMMIT;
								client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, setStatus, 0, NULL);
								RequestEnd(NULL);
								l_free(pkt->size, pkt->ptr);
								return true;
							}
						}
					}
				}
			}
		}
	}*/
	return false;
}

void PgSQL_Session::finishQuery(PgSQL_Data_Stream* myds, PgSQL_Connection* myconn, bool sticky_backend_connection) {
	myds->myconn->reduce_auto_increment_delay_token();
	if (locked_on_hostgroup >= 0) {
		if (qpo->multiplex == -1) {
			myds->myconn->set_status(true, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
		}
	}

	const bool is_active_transaction = myds->myconn->IsActiveTransaction();
	const bool multiplex_disabled_by_status = myds->myconn->MultiplexDisabled(false);

	const bool multiplex_delayed = myds->myconn->auto_increment_delay_token > 0;
	const bool multiplex_delayed_with_timeout =
		!multiplex_disabled_by_status && multiplex_delayed && pgsql_thread___auto_increment_delay_multiplex_timeout_ms > 0;

	const bool multiplex_disabled = !multiplex_disabled_by_status && (!multiplex_delayed || multiplex_delayed_with_timeout);
	const bool conn_is_reusable = myds->myconn->reusable == true && !is_active_transaction && multiplex_disabled;

	if (pgsql_thread___multiplexing && conn_is_reusable) {
		if ((pgsql_thread___connection_delay_multiplex_ms || multiplex_delayed_with_timeout) && mirror == false) {
			if (multiplex_delayed_with_timeout) {
				uint64_t delay_multiplex_us = pgsql_thread___connection_delay_multiplex_ms * 1000;
				uint64_t auto_increment_delay_us = pgsql_thread___auto_increment_delay_multiplex_timeout_ms * 1000;
				uint64_t delay_us = delay_multiplex_us > auto_increment_delay_us ? delay_multiplex_us : auto_increment_delay_us;

				myds->wait_until = thread->curtime + delay_us;
			} else {
				myds->wait_until = thread->curtime + pgsql_thread___connection_delay_multiplex_ms * 1000;
			}

			myconn->async_state_machine = ASYNC_IDLE;
			myconn->multiplex_delayed = true;
			myds->DSS = STATE_MARIADB_GENERIC;
		} else if (sticky_backend_connection == true) {
			myconn->async_state_machine = ASYNC_IDLE;
			myds->DSS = STATE_MARIADB_GENERIC;
			myds->wait_until = 0;
			myconn->multiplex_delayed = false;
		} else {
			myconn->multiplex_delayed = false;
			myds->wait_until = 0;
			myds->DSS = STATE_NOT_INITIALIZED;
			myds->return_MySQL_Connection_To_Pool();
		}
		if (transaction_persistent == true) {
			transaction_persistent_hostgroup = -1;
		}
	} else {
		myconn->multiplex_delayed = false;
		myconn->compute_unknown_transaction_status();
		myconn->async_state_machine = ASYNC_IDLE;
		myds->DSS = STATE_MARIADB_GENERIC;
		if (transaction_persistent == true) {
			if (transaction_persistent_hostgroup == -1) { // change only if not set already, do not allow to change it again
				if (myds->myconn->IsActiveTransaction() == true) { // only active transaction is important here. Ignore other criterias
					transaction_persistent_hostgroup = current_hostgroup;
				}
			} else {
				if (myds->myconn->IsActiveTransaction() == false) { // a transaction just completed
					transaction_persistent_hostgroup = -1;
				}
			}
		}
	}
}

bool PgSQL_Session::known_query_for_locked_on_hostgroup(uint64_t digest) {
	bool ret = false;
	/*switch (digest) {
	case 1732998280766099668ULL: // "SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT"
		ret = true;
		break;
	default:
		break;
	}*/
	return ret;
}

void PgSQL_Session::unable_to_parse_set_statement(bool* lock_hostgroup) {
	// we couldn't parse the query
	string query_str = string((char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
	string digest_str = string(CurrentQuery.get_digest_text());
	const string& nqn = (pgsql_thread___parse_failure_logs_digest == true ? digest_str : query_str);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", query_str.c_str());
	if (qpo->multiplex == -1) {
		// we have no rule about this SET statement. We set hostgroup locking
		if (locked_on_hostgroup < 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "SET query to cause setting lock_hostgroup: %s\n", nqn.c_str());
			if (known_query_for_locked_on_hostgroup(CurrentQuery.QueryParserArgs.digest)) {
				proxy_info("Setting lock_hostgroup for SET query: %s\n", nqn.c_str());
			} else {
				if (client_myds && client_myds->addr.addr) {
					proxy_warning("Unable to parse unknown SET query from client %s:%d. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", client_myds->addr.addr, client_myds->addr.port, nqn.c_str());
				} else {
					proxy_warning("Unable to parse unknown SET query. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", nqn.c_str());
				}
			}
			*lock_hostgroup = true;
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "SET query to cause setting lock_hostgroup, but already set: %s\n", nqn.c_str());
			if (known_query_for_locked_on_hostgroup(CurrentQuery.QueryParserArgs.digest)) {
				//proxy_info("Setting lock_hostgroup for SET query: %s\n", nqn.c_str());
			} else {
				if (client_myds && client_myds->addr.addr) {
					proxy_warning("Unable to parse unknown SET query from client %s:%d. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", client_myds->addr.addr, client_myds->addr.port, nqn.c_str());
				} else {
					proxy_warning("Unable to parse unknown SET query. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", nqn.c_str());
				}
			}
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5,
			"Unable to parse SET query but NOT setting lock_hostgroup %s\n", query_str.c_str());
	}
}

void PgSQL_Session::detected_broken_connection(const char* file, unsigned int line, const char* func, const char* action, PgSQL_Connection* myconn, bool verbose) {
	
	const char* code = PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION);;
	const char* msg = "Detected offline server prior to statement execution";

	if (myconn->is_error_present() == true) {
		code = myconn->get_error_code_str();
		msg = myconn->get_error_message().c_str();
	}
	
	unsigned long long last_used = thread->curtime - myconn->last_time_used;
	last_used /= 1000;
	if (verbose) {
		proxy_error_inline(file, line, func, "Detected a broken connection while %s on (%d,%s,%d,%d) , FD (Conn:%d , MyDS:%d) , user %s , last_used %llums ago : %s, %s\n", action, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_backend_pid(), myconn->myds->fd, myconn->fd, myconn->userinfo->username, last_used, code, msg);
	} else {
		proxy_error_inline(file, line, func, "Detected a broken connection while %s on (%d,%s,%d,%d) , user %s , last_used %llums ago : %s, %s\n", action, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_backend_pid(), myconn->userinfo->username, last_used, code, msg);
	}
}

void PgSQL_Session::generate_status_one_hostgroup(int hid, std::string& s) {
	SQLite3_result* resultset = PgHGM->SQL3_Connection_Pool(false, &hid);
	json j_res;
	if (resultset->rows_count) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			json j; // one json for each row
			for (int i = 0; i < resultset->columns; i++) {
				// using the format j["name"] == "value"
				j[resultset->column_definition[i]->name] = (r->fields[i] ? std::string(r->fields[i]) : std::string("(null)"));
			}
			j_res.push_back(j); // the row json is added to the final json
		}
	}
	else {
		j_res = json::array();
	}
	s = j_res.dump();
	delete resultset;
}

/**
 * @brief Sets the previous status of the PgSQL session according to the current status, with an option to allow EXECUTE statements.
 *
 * This method updates the previous status of the PgSQL session based on its current status. It employs a switch statement
 * to determine the current status and then pushes the corresponding status value onto the `previous_status` stack. If the
 * `allow_execute` parameter is set to true and the current status is `PROCESSING_STMT_EXECUTE`, the method pushes this status
 * onto the stack; otherwise, it skips pushing the status for EXECUTE statements. If the current status does not match any known
 * status value (which should not occur under normal circumstances), the method asserts to indicate a programming error.
 * It currently works with only 3 possible status:
 * - PROCESSING_QUERY
 * - PROCESSING_STMT_PREPARE
 * - PROCESSING_STMT_EXECUTE
 *
 * @param allow_execute A boolean value indicating whether to allow the status of EXECUTE statements to be pushed onto the
 * `previous_status` stack. If set to true, the method will include EXECUTE statements in the session's status history.
 *
 * @return void.
 * @note This method assumes that the `status` member variable has been properly initialized with one of the predefined
 * status values.
 * @note This method is primarily used to maintain a history of the session's previous states for later reference or
 * recovery purposes.
 * @note The LCOV_EXCL_START and LCOV_EXCL_STOP directives are used to exclude the assert statement from code coverage
 * analysis because the condition should not occur during normal execution and is included as a safeguard against
 * programming errors.
 */
void PgSQL_Session::set_previous_status_mode3(bool allow_execute) {
	switch (status) {
	case PROCESSING_QUERY:
		previous_status.push(PROCESSING_QUERY);
		break;
	case PROCESSING_STMT_PREPARE:
		previous_status.push(PROCESSING_STMT_PREPARE);
		break;
	case PROCESSING_STMT_DESCRIBE:
		previous_status.push(PROCESSING_STMT_DESCRIBE);
		break;
	case PROCESSING_STMT_EXECUTE:
		if (allow_execute == true) {
			previous_status.push(PROCESSING_STMT_EXECUTE);
			break;
		}
	
	default:
		// LCOV_EXCL_START
		assert(0); // Assert to indicate an unexpected status value
		break;
		// LCOV_EXCL_STOP
	}
}

void PgSQL_Session::switch_normal_to_fast_forward_mode(PtrSize_t& pkt, std::string_view command, SESSION_FORWARD_TYPE session_type) {

	if (session_fast_forward || session_type == SESSION_FORWARD_TYPE_PERMANENT) return;

	// we use a switch to write the command in the info message
	std::string client_info;
	// we add the client details in the info message
	if (client_myds && client_myds->addr.addr) {
		client_info += " from client " + std::string(client_myds->addr.addr) + ":" + std::to_string(client_myds->addr.port);
	}
	proxy_info("Received command '%s'%s. Switching to Fast Forward mode (Session Type:0x%02X)\n",
		command.data(), client_info.c_str(), session_type);
	session_fast_forward = session_type;

	if (client_myds->PSarrayIN->len) {
		proxy_error("UNEXPECTED PACKET FROM CLIENT -- PLEASE REPORT A BUG\n");
		assert(0);
	}

	mybe->server_myds->reinit_queues(); // reinitialize the queues in the myds . By default, they are not active
	// We reinitialize the 'wait_until' since this session shouldn't wait for processing as
	// we are now transitioning to 'FAST_FORWARD'.
	mybe->server_myds->wait_until = 0;
	assert(mybe->server_myds->DSS != STATE_NOT_INITIALIZED);

	// In case of having a connection, we need to make user to reset the state machine
	// for current server 'PgSQL_Data_Stream'
	mybe->server_myds->DSS = STATE_READY;
	// myds needs to have encrypted value set correctly
		
	PgSQL_Data_Stream* myds = mybe->server_myds;
	PgSQL_Connection* myconn = myds->myconn;
	assert(myconn != NULL);

	// if backend connection uses SSL we will set
	// encrypted = true and we will start using the SSL structure
	// directly from PGconn SSL structure.
	if (myconn->is_connected() && myconn->get_pg_ssl_in_use()) {
		SSL* ssl_obj = myconn->get_pg_ssl_object();
		if (ssl_obj != NULL) {
			myds->encrypted = true;
			myds->ssl = ssl_obj;
			myds->rbio_ssl = BIO_new(BIO_s_mem());
			myds->wbio_ssl = BIO_new(BIO_s_mem());
			SSL_set_bio(myds->ssl, myds->rbio_ssl, myds->wbio_ssl);
		} else {
			// it means that ProxySQL tried to use SSL to connect to the backend
			// but the backend didn't support SSL		
		}
	}
	set_status(FAST_FORWARD); // we can set status to FAST_FORWARD
	//client_myds->PSarrayIN->add(pkt.ptr, pkt.size);
	mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);

	// as we are in FAST_FORWARD mode, we directly send the packet to the backend.
	// need to reset mysql_real_query
	mybe->server_myds->pgsql_real_query.reset();
}

void PgSQL_Session::switch_fast_forward_to_normal_mode() {
	if (session_fast_forward == SESSION_FORWARD_TYPE_NONE) return;

	// only handle temporary session ff
	if (session_fast_forward & SESSION_FORWARD_TYPE_TEMPORARY) {
		// we use a switch to write the command in the info message
		std::string client_info;
		// we add the client details in the info message
		if (client_myds && client_myds->addr.addr) {
			client_info += " for client " + std::string(client_myds->addr.addr) + ":" + std::to_string(client_myds->addr.port);
		}

		proxy_info("Switching back to Normal mode (Session Type:0x%02X)%s\n", 
			session_fast_forward, client_info.c_str());
		session_fast_forward = SESSION_FORWARD_TYPE_NONE;
		PgSQL_Data_Stream* myds = mybe->server_myds;
		PgSQL_Connection* myconn = myds->myconn;
		if (myds->encrypted == true) {
			myds->encrypted = false;
			myds->ssl = NULL;
		}
		RequestEnd(myds);
		finishQuery(myds, myconn, false);
	} else {
		// cannot switch Permanent Fast Forward to Normal
		assert(0);
	}
}

void PgSQL_Session::handle_post_sync_error(PGSQL_ERROR_CODES errcode, const char* errmsg, bool fatal) {
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_error_packet(true, true, errmsg, errcode, fatal, true);
	client_myds->DSS = STATE_SLEEP;
	status = WAITING_CLIENT_DATA;
}

void PgSQL_Session::handle_post_sync_locked_on_hostgroup_error(const char* query, int query_len) {
	client_myds->DSS = STATE_QUERY_SENT_NET;
	int l = query_len;
	char* end = (char*)"";
	if (l > 256) {
		l = 253;
		end = (char*)"...";
	}
	std::string nqn = string(query, l); // truncate string to 253 characters
	const char* err_msg = "Session trying to reach HG %d while locked on HG %d . Rejecting query: %s%s";
	char* buf = (char*)malloc(strlen(err_msg) + strlen(nqn.c_str()) + strlen(end) + 64);
	sprintf(buf, err_msg, current_hostgroup, locked_on_hostgroup, nqn.c_str(), end);
	client_myds->myprot.generate_error_packet(true, true, buf, PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION,
		false, true);
	free(buf);
	thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
	RequestEnd(NULL);
}

int PgSQL_Session::handle_post_sync_parse_message(PgSQL_Parse_Message* parse_msg) {
	PROXY_TRACE();
	thread->status_variables.stvar[st_var_frontend_stmt_prepare]++;
	thread->status_variables.stvar[st_var_queries]++;

	bool lock_hostgroup = false;
	const PgSQL_Parse_Data& parse_data = parse_msg->data();
	PgSQL_Extended_Query_Info& extended_query_info = CurrentQuery.extended_query_info;

	CurrentQuery.begin((unsigned char*)parse_data.query_string, strlen(parse_data.query_string) + 1, false);
	// parse_msg memory will be freed in pgsql_real_query.end(), if message is sent to backend server
	// CurrentQuery.stmt_client_name may briefly become a dangling pointer until CurrentQuery.end() is invoked
	extended_query_info.stmt_client_name = parse_data.stmt_name;

	timespec begint;
	timespec endt;
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begint);
	}
	qpo = GloPgQPro->process_query(this, (unsigned char*)parse_data.query_string, strlen(parse_data.query_string) + 1, &CurrentQuery);
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &endt);
		thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
			(endt.tv_sec * 1000000000 + endt.tv_nsec) -
			(begint.tv_sec * 1000000000 + begint.tv_nsec);
	}
	assert(qpo);	// GloPgQPro->process_mysql_query() should always return a qpo
	
	if (parse_data.num_param_types > 0) {
		Parse_Param_Types parse_param_type;
		parse_param_type.resize(parse_data.num_param_types);
		auto param_type_reader = parse_msg->get_param_types_reader(); // get the reader for the param types
		for (uint16_t i = 0; i < parse_data.num_param_types; ++i) {
			if (!param_type_reader.next(&parse_param_type[i])) {
				proxy_error("Failed to read result format at index %u\n", i);
				return 2;
			}
		}
		CurrentQuery.extended_query_info.parse_param_types = std::move(parse_param_type);
	}

	auto parse_pkt = parse_msg->detach(); // detach the packet from the parse message

	// setting 'prepared' to prevent fetching results from the cache if the digest matches
	bool handled_in_handler = handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(&parse_pkt, &lock_hostgroup, PGSQL_EXTENDED_QUERY_TYPE_PARSE);
	if (handled_in_handler == true)
		// no need to release parse_pkt, it has been released in handler
		return 0;

	if (pgsql_thread___set_query_lock_on_hostgroup == 1) { 
		if (locked_on_hostgroup < 0) {
			if (lock_hostgroup) {
				// we are locking on hostgroup now
				locked_on_hostgroup = current_hostgroup;
			}
		}
		if (locked_on_hostgroup >= 0) {
			if (current_hostgroup != locked_on_hostgroup) {
				handle_post_sync_locked_on_hostgroup_error((const char*)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
				RequestEnd(NULL);
				l_free(parse_pkt.size, parse_pkt.ptr);
				return 2;
			}
		}
	}

	// if the same statement name is used, we drop it
	PgSQL_STMTs_local_v14* local_stmts = client_myds->myconn->local_stmts;
	std::string stmt_name(extended_query_info.stmt_client_name);

	if (auto it = local_stmts->stmt_name_to_global_ids.find(stmt_name);
		it != local_stmts->stmt_name_to_global_ids.end()) {

		if (!stmt_name.empty()) {
			const std::string& errmsg = "prepared statement \"" + stmt_name + "\" already exist";
			handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_DUPLICATE_PSTATEMENT,
				errmsg.c_str(), false);
			l_free(parse_pkt.size, parse_pkt.ptr);
			return 2;
		}

		uint64_t global_id = it->second;
		auto range = local_stmts->global_id_to_stmt_names.equal_range(global_id);

		for (auto iter = range.first; iter != range.second; ++iter) {
			if (iter->second == stmt_name) {
				local_stmts->global_id_to_stmt_names.erase(iter);
				break;
			}
		}

		local_stmts->stmt_name_to_global_ids.erase(it);
		local_stmts->client_close(stmt_name);
	}

	// Hash the query
	uint64_t hash = local_stmts->compute_hash(
		client_myds->myconn->userinfo->username,
		client_myds->myconn->userinfo->dbname,
		(const char*)CurrentQuery.QueryPointer,
		CurrentQuery.QueryLength,
		CurrentQuery.extended_query_info.parse_param_types
	);

	// Check global statement cache
	GloPgStmt->wrlock();
	PgSQL_STMT_Global_info* stmt_info = GloPgStmt->find_prepared_statement_by_hash(hash, false);
	if (stmt_info) {
		local_stmts->client_insert(stmt_info->statement_id, stmt_name);
		extended_query_info.stmt_global_id = stmt_info->statement_id;
		GloPgStmt->unlock();
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		char txn_state = NumActiveTransactions() > 0 ? 'T' : 'I';
		bool send_ready_packet = extended_query_frame.empty();
		client_myds->myprot.generate_parse_completion_packet(true, send_ready_packet, txn_state);
		//LogQuery(nullptr);
		//CurrentQuery.end_time = thread->curtime;
		RequestEnd(NULL);
		l_free(parse_pkt.size, parse_pkt.ptr);
		return 0;
	}
	GloPgStmt->unlock();

	// Fallback: forward to backend
	mybe = find_or_create_backend(current_hostgroup);
	status = PROCESSING_STMT_PREPARE;

	mybe->server_myds->connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
	mybe->server_myds->wait_until = 0;
	mybe->server_myds->killed_at = 0;
	mybe->server_myds->kill_type = 0;

	mybe->server_myds->pgsql_real_query.init(&parse_pkt); // Transfer packet ownership
	mybe->server_myds->statuses.questions++;

	client_myds->setDSS_STATE_QUERY_SENT_NET();
	return 1;
}

int PgSQL_Session::handle_post_sync_describe_message(PgSQL_Describe_Message* describe_msg) {
	PROXY_TRACE();
	//thread->status_variables.stvar[st_var_frontend_stmt_describe]++; // FIXME
	thread->status_variables.stvar[st_var_queries]++;

	const PgSQL_Describe_Data& describe_data = describe_msg->data();
	const char* stmt_client_name = NULL;
	const char* portal_name = NULL;
	bool lock_hostgroup = false;
	uint8_t stmt_type = describe_data.stmt_type;

	switch (stmt_type) {
	case 'P': // Portal
		if (describe_data.stmt_name[0] != '\0') {
			// we don't support named portals yet
			handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
				"only unnamed portals are supported", false);
			return 2;
		}

		// if we are describing a portal, Bind message must exists
		if (!bind_waiting_for_execute) {
			const std::string& errmsg = "portal \"" + std::string(describe_data.stmt_name) + "\" does not exist";
			handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_CURSOR, errmsg.c_str(), false);
			return 2;
		}

		if (extended_query_frame.empty() == false) {
			// Peeking next message in the extended query frame
			// Assuming the client follows correct Bind/Describe/Execute order,
			// we can skip this Describe message, as libpq's PQsendQueryPrepared already sends it.
			if (std::holds_alternative<std::unique_ptr<PgSQL_Execute_Message>>(extended_query_frame.front())) {
				return 0; 
			}
		}

		portal_name = describe_data.stmt_name; // currently only supporting unanmed portals
		stmt_client_name = bind_waiting_for_execute->data().stmt_name; // data() will always be a valid pointer
		assert(strcmp(portal_name, bind_waiting_for_execute->data().portal_name) == 0); // portal name should match the one in bind_waiting_for_execute 
		break;
	case 'S': // Statement
		stmt_client_name = describe_data.stmt_name;
		break;
	default:
		assert(0); // Invalid statement type, should never happen
	}
	assert(stmt_client_name);

	uint64_t stmt_global_id = client_myds->myconn->local_stmts->find_global_id_from_stmt_name(stmt_client_name);
	if (stmt_global_id == 0) {
		const std::string& errmsg = stmt_client_name[0] != '\0' ? ("prepared statement \"" + std::string(stmt_client_name) + "\" does not exist") :
			"unnamed prepared statement does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_SQL_STATEMENT_NAME, errmsg.c_str(), false);
		return 2;
	}

	// now we get the statement information
	PgSQL_STMT_Global_info* stmt_info = GloPgStmt->find_prepared_statement_by_stmt_id(stmt_global_id);
	if (stmt_info == NULL) {
		// we couldn't find it
		const std::string& errmsg = stmt_client_name[0] != '\0' ? ("prepared statement \"" + std::string(stmt_client_name) + "\" does not exist") :
			"unnamed prepared statement does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_SQL_STATEMENT_NAME, errmsg.c_str(), false);
		return 2;
	}
    // describe_msg memory will be freed in pgsql_real_query.end()
    // CurrentQuery.stmt_client_name may briefly become a dangling pointer until CurrentQuery.end() is invoked
	PgSQL_Extended_Query_Info& extended_query_info = CurrentQuery.extended_query_info;
	extended_query_info.stmt_client_name = stmt_client_name;
	extended_query_info.stmt_client_portal_name = portal_name;
	extended_query_info.stmt_global_id = stmt_global_id;
	extended_query_info.stmt_info = stmt_info;
	extended_query_info.stmt_type = stmt_type;
	CurrentQuery.start_time = thread->curtime;

	timespec begint;
	timespec endt;
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begint);
	}
	qpo = GloPgQPro->process_query(this, nullptr, 0, &CurrentQuery);
	assert(qpo);	// GloPgQPro->process_mysql_query() should always return a qpo

	if (qpo->max_lag_ms >= 0) {
		thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
	}
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &endt);
		thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
			(endt.tv_sec * 1000000000 + endt.tv_nsec) -
			(begint.tv_sec * 1000000000 + begint.tv_nsec);
	}
	
	// Use cached stmt_metadata only for statements; for portals, forward the describe request to backend.
	if (extended_query_info.stmt_type == 'S') {
		stmt_info->rdlock();
		if (stmt_info->stmt_metadata) {
			// we have the metadata, so we can send it to the client
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			bool send_ready_packet = extended_query_frame.empty();
			unsigned int nTxn = NumActiveTransactions();
			const char txn_state = (nTxn ? 'T' : 'I');
			client_myds->myprot.generate_describe_completion_packet(true, send_ready_packet, stmt_info->stmt_metadata, 
				extended_query_info.stmt_type, txn_state);
			stmt_info->unlock();
			//LogQuery(NULL);
			//CurrentQuery.end_time = thread->curtime;
			RequestEnd(NULL);
			return 0;
		}
		stmt_info->unlock();
	}

	auto describe_pkt = describe_msg->detach(); // detach the packet from the describe message
	// setting 'prepared' to prevent fetching results from the cache if the digest matches
	bool handled_in_handler = handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(&describe_pkt, 
		&lock_hostgroup, PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE);
	if (handled_in_handler == true) {
		// no need to free describe_pkt, it is already freed in the handler
		return 0;
	}

	if (pgsql_thread___set_query_lock_on_hostgroup == 1) {
		if (locked_on_hostgroup < 0) {
			if (lock_hostgroup) {
				// we are locking on hostgroup now
				locked_on_hostgroup = current_hostgroup;
			}
		}
		if (locked_on_hostgroup >= 0) {
			if (current_hostgroup != locked_on_hostgroup) {
				handle_post_sync_locked_on_hostgroup_error(CurrentQuery.extended_query_info.stmt_info->query, 
					CurrentQuery.extended_query_info.stmt_info->query_length);
				RequestEnd(NULL);
				l_free(describe_pkt.size, describe_pkt.ptr);
				return 2;
			}
		}
	}
	
	mybe = find_or_create_backend(current_hostgroup);
	status = PROCESSING_STMT_DESCRIBE;
	mybe->server_myds->connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
	mybe->server_myds->wait_until = 0;
	pause_until = 0;
	mybe->server_myds->killed_at = 0;
	mybe->server_myds->kill_type = 0;
	mybe->server_myds->pgsql_real_query.init(&describe_pkt); // Transfer packet ownership
	mybe->server_myds->statuses.questions++;
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	return 1;
}

int PgSQL_Session::handle_post_sync_close_message(PgSQL_Close_Message* close_msg) {
	PROXY_TRACE();
	thread->status_variables.stvar[st_var_frontend_stmt_close]++;
	thread->status_variables.stvar[st_var_queries]++;
	
	const PgSQL_Close_Data& close_data = close_msg->data(); // this will always be a valid pointer
	uint8_t stmt_type = close_data.stmt_type;
	
	switch (stmt_type) {
	case 'P': // Portal
		if (close_data.stmt_name[0] != '\0') {
			// we don't support unnamed portals yet
			handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, "only unnamed portals are supported", false);
			return 2;
		}
		bind_waiting_for_execute.reset(nullptr); // release the ownership of the bind message
		break;
	case 'S': // Statement
		client_myds->myconn->local_stmts->client_close(close_data.stmt_name);
		break;
	default:
		assert(0); // this should never occur
	}

	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTxn = NumActiveTransactions();
	char txn_state = (nTxn ? 'T' : 'I');
	bool send_ready = extended_query_frame.empty();
	client_myds->myprot.generate_close_completion_packet(true, send_ready, txn_state);
	client_myds->DSS = STATE_SLEEP;
	status = WAITING_CLIENT_DATA;
	return 0;
}

int PgSQL_Session::handle_post_sync_bind_message(PgSQL_Bind_Message* bind_msg) {
	PROXY_TRACE();
	//thread->status_variables.stvar[st_var_frontend_stmt_bind]++;
	thread->status_variables.stvar[st_var_queries]++;

	const PgSQL_Bind_Data& bind_data = bind_msg->data();

	if (bind_data.portal_name[0] != '\0') {
		// we don't support portals yet
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, "only unnamed portals are supported", false);
		return 2;
	}
	
	const char* stmt_client_name = bind_data.stmt_name;

	uint64_t stmt_global_id = client_myds->myconn->local_stmts->find_global_id_from_stmt_name(stmt_client_name);
	if (stmt_global_id == 0) {
		const std::string& errmsg = stmt_client_name[0] != '\0' ? ("prepared statement \"" + std::string(stmt_client_name) + "\" does not exist") :
			"unnamed prepared statement does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_SQL_STATEMENT_NAME, errmsg.c_str(), false);
		return 2;
	}

	bind_waiting_for_execute.reset(bind_msg->release()); // release the ownership of the bind message
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTxn = NumActiveTransactions();
	char txn_state = (nTxn ? 'T' : 'I');
	bool send_ready = extended_query_frame.empty();
	client_myds->myprot.generate_bind_completion_packet(true, send_ready, txn_state);
	client_myds->DSS = STATE_SLEEP;
	status = WAITING_CLIENT_DATA;
	return 0;
}

int PgSQL_Session::handle_post_sync_execute_message(PgSQL_Execute_Message* execute_msg) {
	PROXY_TRACE();
	//thread->status_variables.stvar[st_var_frontend_stmt_describe]++; // FIXME
	thread->status_variables.stvar[st_var_queries]++;

	bool lock_hostgroup = false;
	const PgSQL_Execute_Data& execute_data = execute_msg->data();

	if (execute_data.portal_name[0] != '\0') {
		// we don't support named portals yet
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED, "only unnamed portals are supported", false);
		return 2;
	}

	const char* portal_name = execute_data.portal_name; 
	if (!bind_waiting_for_execute) {
		const std::string& errmsg = "portal \"" + std::string(portal_name) + "\" does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_CURSOR, errmsg.c_str(), false);
		return 2;
	}
	assert(strcmp(portal_name, bind_waiting_for_execute->data().portal_name) == 0); // portal name should match the one in bind_waiting_for_execute

	// bind_waiting_for_execute will be released on CurrentQuery.end() call or session destory
	const char* stmt_client_name = bind_waiting_for_execute->data().stmt_name;
	uint64_t stmt_global_id = client_myds->myconn->local_stmts->find_global_id_from_stmt_name(stmt_client_name);
	if (stmt_global_id == 0) {
		const std::string& errmsg = stmt_client_name[0] != '\0' ? ("prepared statement \"" + std::string(stmt_client_name) + "\" does not exist") :
			"unnamed prepared statement does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_SQL_STATEMENT_NAME, errmsg.c_str(), false);
		return 2;
	}

	// now we get the statement information
	PgSQL_STMT_Global_info* stmt_info = GloPgStmt->find_prepared_statement_by_stmt_id(stmt_global_id);
	if (stmt_info == NULL) {
		// we couldn't find it
		const std::string& errmsg = stmt_client_name[0] != '\0' ? ("prepared statement \"" + std::string(stmt_client_name) + "\" does not exist") :
			"unnamed prepared statement does not exist";
		handle_post_sync_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_SQL_STATEMENT_NAME, errmsg.c_str(), false);
		return 2;
	}

	PgSQL_Extended_Query_Info& extended_query_info = CurrentQuery.extended_query_info;
	extended_query_info.stmt_client_portal_name = portal_name;
	extended_query_info.stmt_client_name = stmt_client_name;
	extended_query_info.stmt_global_id = stmt_global_id;
	extended_query_info.stmt_info = stmt_info;
	extended_query_info.bind_msg = bind_waiting_for_execute.get();
	CurrentQuery.start_time = thread->curtime;

	timespec begint;
	timespec endt;
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begint);
	}
	qpo = GloPgQPro->process_query(this, nullptr, 0, &CurrentQuery);
	assert(qpo);	// GloPgQPro->process_mysql_query() should always return a qpo

	// required for SET statement parsing
	CurrentQuery.QueryPointer = (unsigned char*)stmt_info->query;
	CurrentQuery.QueryLength = stmt_info->query_length;
	CurrentQuery.QueryParserArgs.digest = stmt_info->digest;
	CurrentQuery.QueryParserArgs.digest_text = stmt_info->digest_text ? strdup(stmt_info->digest_text) : nullptr;
	CurrentQuery.QueryParserArgs.first_comment = stmt_info->first_comment ? strdup(stmt_info->first_comment) : nullptr;
	//

	if (qpo->max_lag_ms >= 0) {
		thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
	}
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID, &endt);
		thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
			(endt.tv_sec * 1000000000 + endt.tv_nsec) -
			(begint.tv_sec * 1000000000 + begint.tv_nsec);
	}

	auto execute_pkt = execute_msg->detach(); // detach the packet from the describe message
	// setting 'prepared' to prevent fetching results from the cache if the digest matches
	bool handled_in_handler = handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_QUERY_qpo(&execute_pkt, &lock_hostgroup, PGSQL_EXTENDED_QUERY_TYPE_EXECUTE);
	if (handled_in_handler == true) {
		// no need to free execute_pkt, it is already freed in the handler
		return 0;
	}

	if (pgsql_thread___set_query_lock_on_hostgroup == 1) {
		if (locked_on_hostgroup < 0) {
			if (lock_hostgroup) {
				// we are locking on hostgroup now
				locked_on_hostgroup = current_hostgroup;
			}
		}
		if (locked_on_hostgroup >= 0) {
			if (current_hostgroup != locked_on_hostgroup) {
				handle_post_sync_locked_on_hostgroup_error(CurrentQuery.extended_query_info.stmt_info->query,
					CurrentQuery.extended_query_info.stmt_info->query_length);
				RequestEnd(NULL);
				l_free(execute_pkt.size, execute_pkt.ptr);
				return 2;
			}
		}
	}
	mybe = find_or_create_backend(current_hostgroup);
	status = PROCESSING_STMT_EXECUTE;
	mybe->server_myds->connect_retries_on_failure = pgsql_thread___connect_retries_on_failure;
	mybe->server_myds->wait_until = 0;
	pause_until = 0;
	mybe->server_myds->killed_at = 0;
	mybe->server_myds->kill_type = 0;
	mybe->server_myds->pgsql_real_query.init(&execute_pkt); // Transfer ownership of the packet
	mybe->server_myds->statuses.questions++;
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	return 1;
}

void PgSQL_Session::reset_extended_query_frame() {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Session=%p client_myds=%p. Discarding all '%lu' messages in extended query frame\n",
		this, client_myds, extended_query_frame.size());
	// Reset the extended query frame and bind to execute
	while (!extended_query_frame.empty()) {
		extended_query_frame.pop();
	}
	bind_waiting_for_execute.reset(nullptr);
}

int  PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_SYNC() {
	PROXY_TRACE();
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return 0;
	}

	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Session=%p client_myds=%p. Processing '%lu' pending messages in extended query frame\n",
		this, client_myds, extended_query_frame.size());

	if (extended_query_frame.empty()) {
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTxn = NumActiveTransactions();
		const char txn_state = (nTxn ? 'T' : 'I');
		client_myds->myprot.generate_ready_for_query_packet(true, txn_state);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return 0;
	}

	return handler___status_PROCESSING_EXTENDED_QUERY_SYNC();
}

int PgSQL_Session::handler___status_PROCESSING_EXTENDED_QUERY_SYNC() {
	PROXY_TRACE();
	// we have pending packets, so we will process them now
	auto packet = std::move(extended_query_frame.front()); // get the packet from the queue
	extended_query_frame.pop(); // remove the packet from the queue

	int rc = -1;

	if (const std::unique_ptr<PgSQL_Parse_Message>* parse_msg = std::get_if<std::unique_ptr<PgSQL_Parse_Message>>(&packet)) {
		rc = handle_post_sync_parse_message(parse_msg->get());
	} else if (const std::unique_ptr<PgSQL_Describe_Message>* describe_msg = std::get_if<std::unique_ptr<PgSQL_Describe_Message>>(&packet)) {
		rc = handle_post_sync_describe_message(describe_msg->get());
	} else if (const std::unique_ptr<PgSQL_Close_Message>* close_msg = std::get_if<std::unique_ptr<PgSQL_Close_Message>>(&packet)) {
		rc = handle_post_sync_close_message(close_msg->get());
	} else if (const std::unique_ptr<PgSQL_Bind_Message>* bind_msg = std::get_if<std::unique_ptr<PgSQL_Bind_Message>>(&packet)) {
		rc = handle_post_sync_bind_message(bind_msg->get());
	} else if (const std::unique_ptr<PgSQL_Execute_Message>* execute_msg = std::get_if<std::unique_ptr<PgSQL_Execute_Message>>(&packet)) {
		rc = handle_post_sync_execute_message(execute_msg->get());
	} else {
		proxy_error("Unknown extended query message\n");
		assert(0); // this should never happen
	}

	if (rc == 2) {
		// incase of error, we discard all pending messages
		reset_extended_query_frame();
		rc = 0;
	}

	return rc;
}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_PARSE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return true;
	}
	
	std::unique_ptr<PgSQL_Parse_Message> parse_msg(new PgSQL_Parse_Message());
	bool rc = parse_msg->parse(pkt);
	if (rc == false) {
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "invalid string in message", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			true, true);
		writeout();
		return false;
	}
	extended_query_frame.push(std::move(parse_msg)); // we will process it later, after sync packet
	return true;
}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_DESCRIBE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return true;
	}

	std::unique_ptr<PgSQL_Describe_Message> describe_msg(new PgSQL_Describe_Message());
	bool rc = describe_msg->parse(pkt);
	if (rc == false) {
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "invalid string in message", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			true, true);
		writeout();
		return false;
	}
	extended_query_frame.push(std::move(describe_msg)); // we will process it later, after sync packet
	return true;
}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_CLOSE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return true;
	}
	std::unique_ptr<PgSQL_Close_Message> close_msg(new PgSQL_Close_Message());
	bool rc = close_msg->parse(pkt);
	if (rc == false) {
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "invalid string in message", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			true, true);
		writeout();
		return false;
	}
	extended_query_frame.push(std::move(close_msg)); // we will process it later, after sync packet
	return true;
}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_BIND(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return true;
	}
	std::unique_ptr<PgSQL_Bind_Message> bind_msg(new PgSQL_Bind_Message());
	bool rc = bind_msg->parse(pkt);
	if (rc == false) {
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "invalid string in message", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			true, true);
		writeout();
		return false;
	}
	extended_query_frame.push(std::move(bind_msg)); // we will process it later, after sync packet
	return true;

}

bool PgSQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___PGSQL_EXECUTE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_PGSQL) { // only PgSQL module supports prepared statement!!
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "Prepared statements not supported", PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			false, true);
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		return true;
	}
	std::unique_ptr<PgSQL_Execute_Message> execute_msg(new PgSQL_Execute_Message());
	bool rc = execute_msg->parse(pkt);
	if (rc == false) {
		l_free(pkt.size, pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_error_packet(true, false, "invalid string in message", PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			true, true);
		writeout();
		return false;
	}
	extended_query_frame.push(std::move(execute_msg)); // we will process it later, after sync packet
	return true;

}

bool PgSQL_Session::handler___rc0_PROCESSING_STMT_PREPARE(enum session_status& st, PgSQL_Data_Stream* myds) {
	thread->status_variables.stvar[st_var_backend_stmt_prepare]++;
	uint64_t global_stmtid;

	PgSQL_STMT_Global_info* stmt_info = NULL;
	GloPgStmt->wrlock();
	stmt_info = GloPgStmt->add_prepared_statement(
		(char*)client_myds->myconn->userinfo->username,
		(char*)client_myds->myconn->userinfo->dbname,
		(char*)CurrentQuery.QueryPointer,
		CurrentQuery.QueryLength,
		CurrentQuery.QueryParserArgs.first_comment,
		std::move(CurrentQuery.extended_query_info.parse_param_types),
		false);
	assert(stmt_info); // GloPgStmt->add_prepared_statement() should always return a valid pointer
	if (CurrentQuery.QueryParserArgs.digest_text) {
		if (stmt_info->digest_text == NULL) {
			stmt_info->digest_text = strdup(CurrentQuery.QueryParserArgs.digest_text);
			stmt_info->digest = CurrentQuery.QueryParserArgs.digest;	// copy digest
			stmt_info->PgQueryCmd = CurrentQuery.PgQueryCmd; // copy PgComQueryCmd
			stmt_info->calculate_mem_usage();
		}
	}
	PgSQL_Extended_Query_Info& extended_query_info = CurrentQuery.extended_query_info;
	extended_query_info.stmt_info = stmt_info;
	global_stmtid = stmt_info->statement_id;
	
	myds->myconn->local_stmts->backend_insert(global_stmtid, extended_query_info.stmt_backend_id);
	st = status;
	
	if (previous_status.empty() == false) {
		myds->myconn->async_state_machine = ASYNC_IDLE;
		myds->DSS = STATE_MARIADB_GENERIC;
		st = previous_status.top();
		previous_status.pop();
		GloPgStmt->unlock();
		return true;
	}
	// We only perform the client_insert when there is no previous status, this
	// is, when 'PROCESSING_STMT_PREPARE' is reached directly without transitioning from a previous status
	// like 'PROCESSING_STMT_EXECUTE'.
	assert(extended_query_info.stmt_client_name);
	client_myds->myconn->local_stmts->client_insert(global_stmtid, extended_query_info.stmt_client_name);

	bool send_ready_packet = extended_query_frame.empty();
	char txn_state = myds->myconn->get_transaction_status_char();
	client_myds->myprot.generate_parse_completion_packet(true, send_ready_packet, txn_state);
	LogQuery(myds);
	GloPgStmt->unlock();
	return false;
}

void PgSQL_Session::handler___rc0_PROCESSING_STMT_DESCRIBE_PREPARE(PgSQL_Data_Stream* myds) {
	//thread->status_variables.stvar[st_var_backend_stmt_describe]++;
	const PgSQL_Extended_Query_Info& extended_query_info = CurrentQuery.extended_query_info;
	assert(extended_query_info.stmt_info);
	bool send_ready_packet = extended_query_frame.empty();
	char txn_state = myds->myconn->get_transaction_status_char();
	
	if (extended_query_info.stmt_type == 'S') {
		GloPgStmt->wrlock();
		extended_query_info.stmt_info->update_stmt_metadata(&myds->myconn->stmt_metadata_result);
		client_myds->myprot.generate_describe_completion_packet(true, send_ready_packet, extended_query_info.stmt_info->stmt_metadata,
			extended_query_info.stmt_type, txn_state);
		LogQuery(myds);
		GloPgStmt->unlock();
		if (myds->myconn->stmt_metadata_result) {
			delete myds->myconn->stmt_metadata_result;
			myds->myconn->stmt_metadata_result = NULL;
		}
	} else {
		// For portals, we don't cache metadata
		client_myds->myprot.generate_describe_completion_packet(true, send_ready_packet, myds->myconn->stmt_metadata_result, 
			extended_query_info.stmt_type, txn_state);
		LogQuery(myds);
		if (myds->myconn->stmt_metadata_result) {
			delete myds->myconn->stmt_metadata_result;
			myds->myconn->stmt_metadata_result = NULL;
		}
	}
}

// Optimized single‐pass parser for PostgreSQL DateStyle strings.
// It supports input in one of these forms:
//   - "ISO, MDY"  (two tokens separated by a comma)
//   - "ISO"       (a single token; the second string will be empty)
// Leading and trailing whitespace is removed from each token.
std::vector<std::string> PgSQL_DateStyle_Util::split_datestyle(std::string_view input) {

	if (input.empty())
		return {};

	std::string token1, token2;
	// Reserve capacity in case the input is large (typically not needed for DateStyle)
	token1.reserve(input.size());
	token2.reserve(input.size());

	// Track last non-space character positions; -1 means “none yet.”
	int lastNonSpace1 = -1, lastNonSpace2 = -1;
	// currentToken: 1 = populating token1, 2 = populating token2.
	int currentToken = 1;

	for (char c : input) {
		if (c == ',') {
			// When a comma is encountered, finalize token1 and switch to token2.
			if (currentToken == 1) {
				if (lastNonSpace1 != -1) {
					token1.resize(lastNonSpace1 + 1); // trim trailing whitespace from token1
				}
				currentToken = 2;
			}
			else {
				// More than one comma encountered – not allowed.
				proxy_error("Invalid \"datestyle\" value was provided. %s\n", input.data());
				return {};
			}
		}
		else {
			// Determine which token to fill.
			std::string* currentStr = (currentToken == 1) ? &token1 : &token2;
			int* lastNonSpace = (currentToken == 1) ? &lastNonSpace1 : &lastNonSpace2;

			// Cache is-space check.
			bool is_space = std::isspace(static_cast<unsigned char>(c));
			// Skip leading whitespace for a new token.
			if (currentStr->empty() && is_space) {
				continue;
			}
			// Append the character.
			currentStr->push_back(c);
			// Update lastNonSpace index if the character is not a whitespace.
			if (!is_space) {
				*lastNonSpace = static_cast<int>(currentStr->size()) - 1;
			}
		}
	}

	// Final trimming for the token being built.
	if (currentToken == 1) {
		if (lastNonSpace1 != -1) {
			token1.resize(lastNonSpace1 + 1);
		}
	}
	else { // currentToken == 2
		if (lastNonSpace2 != -1) {
			token2.resize(lastNonSpace2 + 1);
		}
	}

	std::vector<std::string> result;
	result.reserve(2);
	for (const std::string& token : { token1, token2 }) {
		if (!token.empty()) {
			result.emplace_back(token);
		}
	}
	return result;
}

PgSQL_DateStyle_t PgSQL_DateStyle_Util::parse_datestyle(std::string_view input) {
    PgSQL_DateStyleFormat_t newDateStyle = DATESTYLE_FORMAT_NONE;
    PgSQL_DateStyleOrder_t newDateOrder = DATESTYLE_ORDER_NONE;
    bool have_style = false;
    bool have_order = false;
    bool ok = true;

    auto split_tokens = split_datestyle(input);

    if (split_tokens.empty()) {
        return { DATESTYLE_FORMAT_NONE, DATESTYLE_ORDER_NONE };
    }

    for (std::string_view token : split_tokens) {
        const char* tok = token.data();
        if (strcasecmp(tok, "ISO") == 0) {
            if (have_style && newDateStyle != DATESTYLE_FORMAT_ISO)
                ok = false;     /* conflicting styles */
            newDateStyle = DATESTYLE_FORMAT_ISO;
            have_style = true;
        }
        else if (strcasecmp(tok, "SQL") == 0) {
            if (have_style && newDateStyle != DATESTYLE_FORMAT_SQL)
                ok = false;     /* conflicting styles */
            newDateStyle = DATESTYLE_FORMAT_SQL;
            have_style = true;
        }
        else if (strcasecmp(tok, "POSTGRES") == 0) {
            if (have_style && newDateStyle != DATESTYLE_FORMAT_POSTGRES)
                ok = false;     /* conflicting styles */
            newDateStyle = DATESTYLE_FORMAT_POSTGRES;
            have_style = true;
        }
        else if (strcasecmp(tok, "GERMAN") == 0) {
            if (have_style && newDateStyle != DATESTYLE_FORMAT_GERMAN)
                ok = false;     /* conflicting styles */
            newDateStyle = DATESTYLE_FORMAT_GERMAN;
            have_style = true;
            /* GERMAN also sets DMY, unless explicitly overridden */
            if (!have_order)
                newDateOrder = DATESTYLE_ORDER_DMY;
        }
        else if (strcasecmp(tok, "YMD") == 0) {
            if (have_order && newDateOrder != DATESTYLE_ORDER_YMD)
                ok = false;     /* conflicting orders */
            newDateOrder = DATESTYLE_ORDER_YMD;
            have_order = true;
        }
        else if (strcasecmp(tok, "DMY") == 0 ||
			strcasecmp(tok, "EURO") == 0) {
            if (have_order && newDateOrder != DATESTYLE_ORDER_DMY)
                ok = false;     /* conflicting orders */
            newDateOrder = DATESTYLE_ORDER_DMY;
            have_order = true;
        }
        else if (strcasecmp(tok, "MDY") == 0 ||
			strcasecmp(tok, "US") == 0 ||
			strcasecmp(tok, "NONEURO") == 0) {
            if (have_order && newDateOrder != DATESTYLE_ORDER_MDY)
                ok = false;     /* conflicting orders */
            newDateOrder = DATESTYLE_ORDER_MDY;
            have_order = true;
        }
    }

	// if the provided datestyle includes both style and order, ensure both values are valid.
	if (split_tokens.size() == 2 && (have_style && have_order) == false) {
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Invalid \"datestyle\" value. %s\n", input.data());
		return { DATESTYLE_FORMAT_NONE, DATESTYLE_ORDER_NONE };
	}

    if (!ok) {
        proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Conflicting \"datestyle\" value. %s\n", input.data());
        return { DATESTYLE_FORMAT_NONE, DATESTYLE_ORDER_NONE };
    }

    return { newDateStyle, newDateOrder };
}

std::string PgSQL_DateStyle_Util::datestyle_to_string(PgSQL_DateStyle_t datestyle, const PgSQL_DateStyle_t& default_datestyle) {

	if (datestyle.format == DATESTYLE_FORMAT_NONE && datestyle.order == DATESTYLE_ORDER_NONE) {
		return {};
	}

	if (datestyle.format == DATESTYLE_FORMAT_NONE && default_datestyle.format != DATESTYLE_FORMAT_NONE) {
		datestyle.format = default_datestyle.format;
	}

	if (datestyle.order == DATESTYLE_ORDER_NONE && default_datestyle.order != DATESTYLE_ORDER_NONE) {
		datestyle.order = default_datestyle.order;
	}

	std::string result;
	result.reserve(32);
	switch (datestyle.format)
	{
	case DATESTYLE_FORMAT_ISO:
		result.append("ISO");
		break;
	case DATESTYLE_FORMAT_SQL:
		result.append("SQL");
		break;
	case DATESTYLE_FORMAT_GERMAN:
		result.append("German");
		break;
	default:
		result.append("Postgres");
		break;
	}

	switch (datestyle.order)
	{
	case DATESTYLE_ORDER_YMD:
		result.append(", YMD");
		break;
	case DATESTYLE_ORDER_DMY:
		result.append(", DMY");
		break;
	default:
		result.append(", MDY");
		break;
	}

	return result;
}

std::string PgSQL_DateStyle_Util::datestyle_to_string(std::string_view input, const PgSQL_DateStyle_t& default_datestyle) {
	return datestyle_to_string(parse_datestyle(input), default_datestyle);
}

