#include "PgSQL_Set_Stmt_Parser.h"
#include "gen_utils.h"
#include <string>
#include <vector>
#include <map>
#include <cassert>
#include <utility> // for std::pair
//#ifdef PARSERDEBUG
#include <iostream>
//#endif

#ifdef DEBUG
//#define VALGRIND_ENABLE_ERROR_REPORTING
//#define VALGRIND_DISABLE_ERROR_REPORTING
#include "valgrind.h"
#else
#define VALGRIND_ENABLE_ERROR_REPORTING
#define VALGRIND_DISABLE_ERROR_REPORTING
#endif // DEBUG

using namespace std;

#define MULTI_STATEMENTS_USE "Unable to parse multi-statements command with USE statement"

static void remove_quotes(string& v) {
	if (v.length() > 2) {
		char firstChar = v[0];
		char lastChar = v[v.length()-1];
		if (firstChar == lastChar) {
			if (firstChar == '\'' || firstChar == '"' || firstChar == '`') {
				v.erase(v.length()-1, 1);
				v.erase(0, 1);
			}
		}
	}
}

#ifdef PARSERDEBUG
PgSQL_Set_Stmt_Parser::PgSQL_Set_Stmt_Parser(std::string nq, int verb) {
	verbosity = verb;
#else

PgSQL_Set_Stmt_Parser::PgSQL_Set_Stmt_Parser(std::string nq) {
#endif
	parse1v2_init = false;
	set_query(nq);
}

PgSQL_Set_Stmt_Parser::~PgSQL_Set_Stmt_Parser() {
	if (parse1v2_init == true) {
		delete parse1v2_opt2;
		delete parse1v2_re;
	}
}

void PgSQL_Set_Stmt_Parser::set_query(const std::string& nq) {
	int query_no_space_length = nq.length();
	char *query_no_space=(char *)malloc(query_no_space_length+1);
	memcpy(query_no_space,nq.c_str(),query_no_space_length);
	query_no_space[query_no_space_length]='\0';
	query_no_space_length=remove_spaces(query_no_space);
	query = std::string(query_no_space);
	free(query_no_space);
}

void PgSQL_Set_Stmt_Parser::generateRE_parse1v2() {
	
#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
#endif // DEBUG

	// Function Call: Check if Group 3 is populated.
	// Literal: Check if Group 4 is populated.
	const std::string pattern = R"((?:(SESSION)\s+)?((?:TIME\s+ZONE|TRANSACTION\s+ISOLATION\s+LEVEL|XML\s+OPTION|(?:(?:[^\s=]{1,4}|[^\s=]{6,}|(?:[^lL][^\s=]{4}|[lL][^oO][^\s=]{3}|[lL][oO][^cC][^\s=]{2}|[lL][oO][cC][^aA][^\s=]|[lL][oO][cC][aA][^lL])))))(?:\s*=\s*|\s+TO\s+|\s+)(?:([A-Za-z_][\w$\.]*)\s*\(\s*('(?:''|[^'])*'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[^();]+?)\s*\)|('(?:''|[^'])*'|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[^;()]+))\s*;?)";

#ifdef DEBUG
VALGRIND_DISABLE_ERROR_REPORTING;
#endif // DEBUG
#ifdef PARSERDEBUG
	if (verbosity > 0) {
		cout << pattern << endl;
	}
#endif
	parse1v2_opt2 = new re2::RE2::Options(RE2::Quiet);
	parse1v2_opt2->set_case_sensitive(false);
	parse1v2_opt2->set_longest_match(false);

	parse1v2_pattern = pattern;
	parse1v2_re = new re2::RE2(parse1v2_pattern, *parse1v2_opt2);
	
	if (!parse1v2_re->ok()) {
		proxy_error("Error in RE2 regex pattern: %s\n", parse1v2_re->error().c_str());
		assert(false);
	}

	parse1v2_init = true;
}


std::map<std::string,std::vector<std::string>> PgSQL_Set_Stmt_Parser::parse1v2() {

	std::map<std::string,std::vector<std::string>> result = {};

	if (parse1v2_init == false) {
		generateRE_parse1v2();
	}

	re2::RE2 re0("^\\s*SET\\s+", *parse1v2_opt2);
	re2::RE2::Replace(&query, re0, "");
	re2::RE2 re1("(\\s|;)+$", *parse1v2_opt2); // remove trailing spaces and semicolon
	re2::RE2::Replace(&query, re1, "");

#ifdef DEBUG
VALGRIND_ENABLE_ERROR_REPORTING;
#endif // DEBUG
	std::string var;
	std::string scope, param_name, param_val_func, param_val_func_args, param_val;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, *parse1v2_re, &scope, &param_name, &param_val_func, &param_val_func_args, &param_val)) {
		// FIXME: verify if we reached end of query. Did we parse everything?
		std::vector<std::string> op;
#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: scope='%s', parameter name='%s' , parameter value='%s' , parameter_value_func='%s' , parameter_value_func_args='%s'\n", scope.c_str(), param_name.c_str(), param_val.c_str(), param_val_func.c_str(), param_val_func_args.c_str());
#endif // DEBUG
		std::string key;

		if (param_val_func.empty() == false) return {};

		if (param_name.empty() || param_val.empty()) {
			continue;
		}
		
		key = param_name;
		remove_quotes(key);
		size_t pos = param_val.find_last_not_of(" \n\r\t,");
		if (pos != param_val.npos) {
			param_val.erase(pos+1);
		}

		if (param_val == "''" || param_val == "\"\"") {
			op.push_back("");
		} else {
			remove_quotes(param_val);
			op.push_back(param_val);
		}

		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		result[key] = op;
	}
	if (input.size() != 0) {
#ifdef PARSERDEBUG
		if (verbosity > 0) {
			cout << "Failed to parse: " << input << endl;
		}
#endif
		result = {};
	}
	return result;
}


std::map<std::string,std::vector<std::string>> PgSQL_Set_Stmt_Parser::parse2() {

#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
#endif // DEBUG
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");

	std::map<std::string,std::vector<std::string>> result;

	// Regex used:
	// SET(?: +)(|SESSION +)TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))
	const std::string pattern="(|SESSION) *TRANSACTION(?: +)(?:(?:(ISOLATION(?: +)LEVEL)(?: +)(REPEATABLE(?: +)READ|READ(?: +)COMMITTED|READ(?: +)UNCOMMITTED|SERIALIZABLE))|(?:(READ)(?: +)(WRITE|ONLY)))";
	re2::RE2 re(pattern, *opt2);
	std::string var;
	std::string value1, value2, value3, value4, value5;
	re2::StringPiece input(query);
	while (re2::RE2::Consume(&input, re, &value1, &value2, &value3, &value4, &value5)) {
		std::vector<std::string> op;
#ifdef DEBUG
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "SET parsing: v1='%s' , v2='%s' , v3='%s' , v4='%s' , v5='%s'\n", value1.c_str(), value2.c_str(), value3.c_str(), value4.c_str(), value5.c_str());
#endif // DEBUG
		std::string key;
		//if (value1 != "") { // session is specified
			if (value2 != "") { // isolation level
				key = value1 + ":" + value2;
				std::transform(value3.begin(), value3.end(), value3.begin(), ::toupper);
				op.push_back(value3);
			} else {
				key = value1 + ":" + value4;
				std::transform(value5.begin(), value5.end(), value5.begin(), ::toupper);
				op.push_back(value5);
			}
		//}
		std::transform(key.begin(), key.end(), key.begin(), ::tolower);
		result[key] = op;
	}

	delete opt2;
	return result;
}

#if 0
std::string PgSQL_Set_Stmt_Parser::parse_character_set() {
#ifdef DEBUG
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 4, "Parsing query %s\n", query.c_str());
#endif // DEBUG
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt2->set_longest_match(false);

	re2::RE2 re0("^\\s*SET\\s+", *opt2);
	re2::RE2::Replace(&query, re0, "");

	std::map<std::string,std::vector<std::string>> result;
	const std::string pattern = "(client_encoding|names)\\s*(=|TO)\\s*['\"]?([A-Z_0-9]+)['\"]?";
	re2::RE2 re(pattern, *opt2);
	std::string var;
	std::string value1, value2, value3;
	re2::StringPiece input(query);
	re2::RE2::Consume(&input, re, &value1, &value2, &value3);

	delete opt2;
	return value3;
}
#endif
std::string PgSQL_Set_Stmt_Parser::remove_comments(const std::string& q) {
    std::string result = "";
    bool in_multiline_comment = false;

    for (size_t i = 0; i < query.size(); ++i) {
        char current_char = query[i];

        // Check for multiline comment start
        if (current_char == '/' && i + 1 < query.size() && query[i + 1] == '*') {
            in_multiline_comment = true;
            i++; // Skip the '*'
            continue;
        }   

        // Check for multiline comment end
        if (in_multiline_comment && current_char == '*' && i + 1 < query.size() && query[i + 1] == '/') {
            in_multiline_comment = false;
            i++; // Skip the '/'
            continue;
        }   

        // Skip characters inside multiline comment
        if (in_multiline_comment) {
            continue;
        }

        // Check for single-line comments
        if (current_char == '#' || (current_char == '-' && i + 1 < query.size() && query[i + 1] == '-')) {
            // Skip until the end of the line
            while (i < query.size() && query[i] != '\n') {
                i++;
            }
            continue;
        }

        // Append the character to the result if it's not a comment
        result += current_char;
    }

    return result;
}
