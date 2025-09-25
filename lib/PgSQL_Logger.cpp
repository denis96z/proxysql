#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include <fstream>
#include "proxysql.h"
#include "cpp.h"

#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Logger.hpp"

#include <dirent.h>
#include <libgen.h>


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_PGSQL_LOGGER_VERSION "2.5.0421" DEB

extern PgSQL_Logger *GloPgSQL_Logger;

static uint8_t encode_length(uint64_t len, unsigned char *hd) {
	if (len < 251) return 1;
	if (len < 65536) { if (hd) { *hd=0xfc; }; return 3; }
	if (len < 16777216) { if (hd) { *hd=0xfd; }; return 4; }
	if (hd) { *hd=0xfe; }
	return 9;
}

static inline int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix) {
	if (len==1) {
		*p=(char)val;
		return 1;
	}
	*p=prefix;
	p++;
	memcpy(p,&val,len-1);
	return len;
}

PgSQL_Event::PgSQL_Event (PGSQL_LOG_EVENT_TYPE _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
	client=_client;
	client_len=_client_len;
	et=_et;
	hid=UINT64_MAX;
	server=NULL;
	extra_info = NULL;
	have_affected_rows=false;
	affected_rows=0;
	have_rows_sent=false;
	rows_sent=0;
	client_stmt_name=NULL;
}

void PgSQL_Event::set_client_stmt_name(char* client_stmt_name) {
	this->client_stmt_name = client_stmt_name;
}

// if affected rows is set, last_insert_id is set too.
// They are part of the same OK packet
void PgSQL_Event::set_affected_rows(uint64_t ar) {
	have_affected_rows=true;
	affected_rows=ar;
}

void PgSQL_Event::set_rows_sent(uint64_t rs) {
	have_rows_sent=true;
	rows_sent=rs;
}

void PgSQL_Event::set_extra_info(char *_err) {
	extra_info = _err;
}

void PgSQL_Event::set_query(const char *ptr, int len) {
	query_ptr=(char *)ptr;
	// Adjust length: input length includes the null terminator
	if (len > 0) {
		len--;  // exclude '\0'
	}
	query_len=len;
}

void PgSQL_Event::set_server(int _hid, const char *ptr, int len) {
	server=(char *)ptr;
	server_len=len;
	hid=_hid;
}

uint64_t PgSQL_Event::write(std::fstream *f, PgSQL_Session *sess) {
	uint64_t total_bytes=0;
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::SIMPLE_QUERY:
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
			if (pgsql_thread___eventslog_format==1) { // format 1 , binary
				total_bytes=write_query_format_1(f);
			} else { // format 2 , json
				total_bytes=write_query_format_2_json(f);
			}
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
		case PGSQL_LOG_EVENT_TYPE::INITDB:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT:
			write_auth(f, sess);
			break;
		default:
			break;
	}
	return total_bytes;
}

void PgSQL_Event::write_auth(std::fstream *f, PgSQL_Session *sess) {
	json j = {};
	j["timestamp"] = start_time/1000;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(start_time%1000000)/1000);
		j["time"] = buffer2;
	}
	j["thread_id"] = thread_id;
	if (username) {
		j["username"] = username;
	} else {
		j["username"] = "";
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	} else {
		j["schemaname"] = "";
	}
	if (client) {
		j["client_addr"] = client;
	} else {
		j["client_addr"] = "";
	}
	if (server) {
		j["server_addr"] = server;
	}
	if (extra_info) {
		j["extra_info"] = extra_info;
	}
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
			j["event"]="PgSQL_Client_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
			j["event"]="PgSQL_Client_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
			j["event"]="PGSQL_Client_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
			j["event"]="PGSQL_Client_Quit";
			break;
		case PGSQL_LOG_EVENT_TYPE::INITDB:
			j["event"]="PGSQL_Client_Init_DB";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK:
			j["event"]="PGSQL_Admin_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR:
			j["event"]="PGSQL_Admin_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
			j["event"]="PGSQL_Admin_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT:
			j["event"]="PGSQL_Admin_Quit";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK:
			j["event"]="PGSQL_SQLite3_Connect_OK";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR:
			j["event"]="PGSQL_SQLite3_Connect_ERR";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
			j["event"]="PGSQL_SQLite3_Close";
			break;
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT:
			j["event"]="PGSQL_SQLite3_Quit";
			break;
		default:
			break;
	}
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE:
		case PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE:
			{
				uint64_t curtime_real=realtime_time();
				uint64_t curtime_mono=sess->thread->curtime;
				uint64_t timediff = curtime_mono - sess->start_time;
				uint64_t orig_time = curtime_real - timediff;
				time_t timer= (orig_time)/1000/1000;
				struct tm* tm_info;
				tm_info = localtime(&timer);
				char buffer1[36];
				char buffer2[64];
				strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
				sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(orig_time%1000000)/1000);
				j["creation_time"] = buffer2;
				//unsigned long long life = sess->thread->curtime - sess->start_time;
				//life/=1000;
				float f = timediff;
				f /= 1000;
				sprintf(buffer1, "%.3fms", f);
				j["duration"] = buffer1;
			}
			break;
		default:
			break;
	}
	if (sess->client_myds) {
		if (sess->client_myds->proxy_addr.addr) {
			std::string s = sess->client_myds->proxy_addr.addr;
			s += ":" + std::to_string(sess->client_myds->proxy_addr.port);
			j["proxy_addr"] = s;
		}
		j["ssl"] = sess->client_myds->encrypted;
	}
	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
	//move wrlock() function to log_audit_entry() function, avoid to get a null pointer in a multithreaded environment
	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
}

uint64_t PgSQL_Event::write_query_format_1(std::fstream *f) {
	uint64_t total_bytes=0;
	total_bytes+=1; // et
	total_bytes+=encode_length(thread_id, NULL);
	username_len=strlen(username);
	total_bytes+=encode_length(username_len,NULL)+username_len;
	schemaname_len=strlen(schemaname);
	total_bytes+=encode_length(schemaname_len,NULL)+schemaname_len;

	total_bytes+=encode_length(client_len,NULL)+client_len;

	total_bytes+=encode_length(hid, NULL);
	if (hid!=UINT64_MAX) {
		total_bytes+=encode_length(server_len,NULL)+server_len;
	}

	total_bytes+=encode_length(start_time,NULL);
	total_bytes+=encode_length(end_time,NULL);
	client_stmt_name_len=client_stmt_name ? strlen(client_stmt_name) : 0;
	total_bytes+=encode_length(client_stmt_name_len,NULL)+client_stmt_name_len;
	total_bytes+=encode_length(affected_rows,NULL);
	total_bytes+=encode_length(rows_sent,NULL);

	total_bytes+=encode_length(query_digest,NULL);

	total_bytes+=encode_length(query_len,NULL)+query_len;

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	// write total length , fixed size
	f->write((const char *)&total_bytes,sizeof(uint64_t));
	//char prefix;
	uint8_t len;

	f->write((char *)&et,1);

	len=encode_length(thread_id,buf);
	write_encoded_length(buf,thread_id,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(username_len,buf);
	write_encoded_length(buf,username_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(username,username_len);

	len=encode_length(schemaname_len,buf);
	write_encoded_length(buf,schemaname_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(schemaname,schemaname_len);

	len=encode_length(client_len,buf);
	write_encoded_length(buf,client_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(client,client_len);

	len=encode_length(hid,buf);
	write_encoded_length(buf,hid,len,buf[0]);
	f->write((char *)buf,len);

	if (hid!=UINT64_MAX) {
		len=encode_length(server_len,buf);
		write_encoded_length(buf,server_len,len,buf[0]);
		f->write((char *)buf,len);
		f->write(server,server_len);
	}

	len=encode_length(start_time,buf);
	write_encoded_length(buf,start_time,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(end_time,buf);
	write_encoded_length(buf,end_time,len,buf[0]);
	f->write((char *)buf,len);

	if (et == PGSQL_LOG_EVENT_TYPE::STMT_PREPARE || et == PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE || et == PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		len = encode_length(client_stmt_name_len, buf);
		write_encoded_length(buf, client_stmt_name_len, len, buf[0]);
		f->write((char*)buf, len);
		f->write(client_stmt_name, client_stmt_name_len);
	}

	len=encode_length(affected_rows,buf);
	write_encoded_length(buf,affected_rows,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(rows_sent,buf);
	write_encoded_length(buf,rows_sent,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(query_digest,buf);
	write_encoded_length(buf,query_digest,len,buf[0]);
	f->write((char *)buf,len);

	len=encode_length(query_len,buf);
	write_encoded_length(buf,query_len,len,buf[0]);
	f->write((char *)buf,len);
	if (query_len) {
		f->write(query_ptr,query_len);
	}

	return total_bytes;
}

uint64_t PgSQL_Event::write_query_format_2_json(std::fstream *f) {
	json j = {};
	uint64_t total_bytes=0;
	if (hid!=UINT64_MAX) {
		j["hostgroup_id"] = hid;
	} else {
		j["hostgroup_id"] = -1;
	}
	j["thread_id"] = thread_id;
	switch (et) {
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
			j["event"]="PGSQL_STMT_EXECUTE";
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
			j["event"]="PGSQL_STMT_PREPARE";
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
			j["event"]="PGSQL_STMT_DESCRIBE";
			break;
		default:
			j["event"]="PGSQL_SIMPLE_QUERY";
			break;
	}
	if (username) {
		j["username"] = username;
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	}
	if (client) {
		j["client"] = client;
	}
	if (hid!=UINT64_MAX) {
		if (server) {
			j["server"] = server;
		}
	}
	if (have_affected_rows == true) {
		// in JSON format we only log rows_affected and last_insert_id
		// if they are present.
		// rows_affected is logged also if 0, while
		// last_insert_id is log logged if 0
		j["rows_affected"] = affected_rows;
	}
	if (have_rows_sent == true) {
		j["rows_sent"] = rows_sent;
	}
	j["query"] = string(query_ptr, query_len);
	j["starttime_timestamp_us"] = start_time;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(start_time%1000000));
		j["starttime"] = buffer2;
	}
	j["endtime_timestamp_us"] = end_time;
	{
		time_t timer=end_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(end_time%1000000));
		j["endtime"] = buffer2;
	}
	j["duration_us"] = end_time-start_time;
	char digest_hex[20];
	sprintf(digest_hex,"0x%016llX", (long long unsigned int)query_digest);
	j["digest"] = digest_hex;

	if (et == PGSQL_LOG_EVENT_TYPE::STMT_PREPARE || et == PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE || et == PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		if (client_stmt_name) {
			j["client_stmt_name"] = client_stmt_name;
		}
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloPgSQL_Logger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
	return total_bytes; // always 0
}

extern PgSQL_Query_Processor* GloPgQPro;

PgSQL_Logger::PgSQL_Logger() {
	events.enabled=false;
	events.base_filename=NULL;
	events.datadir=NULL;
	events.base_filename=strdup((char *)"");
	audit.enabled=false;
	audit.base_filename=NULL;
	audit.datadir=NULL;
	audit.base_filename=strdup((char *)"");
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_init(&wmutex,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	events.logfile=NULL;
	events.log_file_id=0;
	events.max_log_file_size=100*1024*1024;
	audit.logfile=NULL;
	audit.log_file_id=0;
	audit.max_log_file_size=100*1024*1024;
};

PgSQL_Logger::~PgSQL_Logger() {
	if (events.datadir) {
		free(events.datadir);
	}
	free(events.base_filename);
	if (audit.datadir) {
		free(audit.datadir);
	}
	free(audit.base_filename);
};

void PgSQL_Logger::wrlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_lock(&wmutex);
#else
  spin_wrlock(&rwlock);
#endif
};

void PgSQL_Logger::wrunlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_unlock(&wmutex);
#else
  spin_wrunlock(&rwlock);
#endif
};

void PgSQL_Logger::flush_log() {
	if (audit.enabled==false && events.enabled==false) return;
	wrlock();
	events_flush_log_unlocked();
	audit_flush_log_unlocked();
	wrunlock();
}


void PgSQL_Logger::events_close_log_unlocked() {
	if (events.logfile) {
		events.logfile->flush();
		events.logfile->close();
		delete events.logfile;
		events.logfile=NULL;
	}
}

void PgSQL_Logger::audit_close_log_unlocked() {
	if (audit.logfile) {
		audit.logfile->flush();
		audit.logfile->close();
		delete audit.logfile;
		audit.logfile=NULL;
	}
}

void PgSQL_Logger::events_flush_log_unlocked() {
	if (events.enabled==false) return;
	events_close_log_unlocked();
	events_open_log_unlocked();
}

void PgSQL_Logger::audit_flush_log_unlocked() {
	if (audit.enabled==false) return;
	audit_close_log_unlocked();
	audit_open_log_unlocked();
}

void PgSQL_Logger::events_open_log_unlocked() {
	events.log_file_id=events_find_next_id();
	if (events.log_file_id!=0) {
		events.log_file_id=events_find_next_id()+1;
	} else {
		events.log_file_id++;
	}
	char *filen=NULL;
	if (events.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(events.base_filename)+11);
		sprintf(filen,"%s.%08d",events.base_filename,events.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(events.datadir)+strlen(events.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",events.datadir,events.base_filename,events.log_file_id);
	}
	events.logfile=new std::fstream();
	events.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		events.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new pgsql event log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new pgsql event log file %s\n", filen);
		delete events.logfile;
		events.logfile=NULL;
	}
	free(filen);
};

void PgSQL_Logger::audit_open_log_unlocked() {
	audit.log_file_id=audit_find_next_id();
	if (audit.log_file_id!=0) {
		audit.log_file_id=audit_find_next_id()+1;
	} else {
		audit.log_file_id++;
	}
	char *filen=NULL;
	if (audit.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(audit.base_filename)+11);
		sprintf(filen,"%s.%08d",audit.base_filename,audit.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(audit.datadir)+strlen(audit.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",audit.datadir,audit.base_filename,audit.log_file_id);
	}
	audit.logfile=new std::fstream();
	audit.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		audit.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new pgsql audit log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
		proxy_error("Error creating new pgsql audit log file %s\n", filen);
		delete audit.logfile;
		audit.logfile=NULL;
	}
	free(filen);
};

void PgSQL_Logger::events_set_base_filename() {
	// if filename is the same, return
	wrlock();
	events.max_log_file_size=pgsql_thread___eventslog_filesize;
	if (strcmp(events.base_filename,pgsql_thread___eventslog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	events_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	events.log_file_id=0;
	free(events.base_filename);
	events.base_filename=strdup(pgsql_thread___eventslog_filename);
	if (strlen(events.base_filename)) {
		events.enabled=true;
		events_open_log_unlocked();
	} else {
		events.enabled=false;
	}
	wrunlock();
}

void PgSQL_Logger::events_set_datadir(char *s) {
	if (events.datadir)
		free(events.datadir);
	events.datadir=strdup(s);
	flush_log();
};

void PgSQL_Logger::audit_set_base_filename() {
	// if filename is the same, return
	wrlock();
	audit.max_log_file_size=pgsql_thread___auditlog_filesize;
	if (strcmp(audit.base_filename,pgsql_thread___auditlog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	audit_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	audit.log_file_id=0;
	free(audit.base_filename);
	audit.base_filename=strdup(pgsql_thread___auditlog_filename);
	if (strlen(audit.base_filename)) {
		audit.enabled=true;
		audit_open_log_unlocked();
	} else {
		audit.enabled=false;
	}
	wrunlock();
}

void PgSQL_Logger::audit_set_datadir(char *s) {
	if (audit.datadir)
		free(audit.datadir);
	audit.datadir=strdup(s);
	flush_log();
};

void PgSQL_Logger::log_request(PgSQL_Session *sess, PgSQL_Data_Stream *myds) {
	if (events.enabled==false) return;
	if (events.logfile==NULL) return;
	// 'PgSQL_Session::client_myds' could be NULL in case of 'RequestEnd' being called over a freshly created session
	// due to a failed 'CONNECTION_RESET'. Because this scenario isn't a client request, we just return.
	if (sess->client_myds==NULL || sess->client_myds->myconn== NULL) return;

	PgSQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

	uint64_t curtime_real=realtime_time();
	uint64_t curtime_mono=sess->thread->curtime;
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);
	PGSQL_LOG_EVENT_TYPE let = PGSQL_LOG_EVENT_TYPE::SIMPLE_QUERY; // default
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE;
			break;
		case PROCESSING_STMT_PREPARE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_PREPARE;
			break;
		case PROCESSING_STMT_DESCRIBE:
			let = PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE;
			break;
		case WAITING_CLIENT_DATA:
		case PROCESSING_EXTENDED_QUERY_SYNC:
		{
			switch (sess->get_extended_query_phase() & EXTQ_PHASE_PROCESSING_MASK) {
			case EXTQ_PHASE_PROCESSING_PARSE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_PREPARE;
				break;
			case EXTQ_PHASE_PROCESSING_DESCRIBE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE;
				break;
			case EXTQ_PHASE_PROCESSING_EXECUTE:
				let = PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE;
				break;
			default:
				break;
			}
		}
			break;
		default:
			break;
	}

	uint64_t query_digest = 0;

	if (let != PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE && let != PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE) {
		query_digest = GloPgQPro->get_digest(&sess->CurrentQuery.QueryParserArgs);
	} else {
		query_digest = sess->CurrentQuery.extended_query_info.stmt_info->digest;
	}

	PgSQL_Event me(let,
		sess->thread_session_id,ui->username,ui->dbname,
		sess->CurrentQuery.start_time + curtime_real - curtime_mono,
		sess->CurrentQuery.end_time + curtime_real - curtime_mono,
		query_digest,
		ca, cl
	);
	char *c = NULL;
	int ql = 0;
	switch (let) {
		case PGSQL_LOG_EVENT_TYPE::STMT_DESCRIBE:
		case PGSQL_LOG_EVENT_TYPE::STMT_EXECUTE:
			c = sess->CurrentQuery.extended_query_info.stmt_info->query;
			ql = sess->CurrentQuery.extended_query_info.stmt_info->query_length;
			me.set_client_stmt_name((char*)sess->CurrentQuery.extended_query_info.stmt_client_name);
			break;
		case PGSQL_LOG_EVENT_TYPE::STMT_PREPARE:
		default:
			c = (char *)sess->CurrentQuery.QueryPointer;
			ql = sess->CurrentQuery.QueryLength;
			// NOTE: This needs to be located in the 'default' case because otherwise will miss state
			// 'WAITING_CLIENT_DATA'. This state is possible when the prepared statement is found in the
			// global cache and due to that we immediately reply to the client and session doesn't reach
			// 'PROCESSING_STMT_PREPARE' state. 'stmt_client_id' is expected to be '0' for anything that isn't
			// a prepared statement, still, logging should rely 'PGSQL_LOG_EVENT_TYPE' instead of this value.
			me.set_client_stmt_name((char*)sess->CurrentQuery.extended_query_info.stmt_client_name);
			break;
	}
	if (c) {
		me.set_query(c,ql);
	} else {
		me.set_query("",0);
	}

	if (sess->CurrentQuery.have_affected_rows) {
		me.set_affected_rows(sess->CurrentQuery.affected_rows);
	}
	me.set_rows_sent(sess->CurrentQuery.rows_sent);

	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);
	if (sl) {
		int hid=-1;
		hid=myds->myconn->parent->myhgc->hid;
		me.set_server(hid,sa,sl);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();
	
	//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
        GloPgSQL_Logger->wrlock();

	me.write(events.logfile, sess);


	unsigned long curpos=events.logfile->tellp();
	if (curpos > events.max_log_file_size) {
		events_flush_log_unlocked();
	}
	wrunlock();

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void PgSQL_Logger::log_audit_entry(PGSQL_LOG_EVENT_TYPE _et, PgSQL_Session *sess, PgSQL_Data_Stream *myds, char *xi) {
	if (audit.enabled==false) return;
	if (audit.logfile==NULL) return;

	if (sess == NULL) return;
	if (sess->client_myds == NULL)  return; 

	PgSQL_Connection_userinfo *ui= NULL;
	if (sess) {
		if (sess->client_myds) {
			if (sess->client_myds->myconn) {
				ui = sess->client_myds->myconn->userinfo;
			}
		}
	}
	if (sess) {
		// to reduce complexing in the calling function, we do some changes here
		switch (_et) {
			case PGSQL_LOG_EVENT_TYPE::AUTH_OK:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_OK;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_OK;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_ERR:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_ERR;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_ERR;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_QUIT:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_QUIT;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_QUIT;
					default:
						break;
				}
				break;
			case PGSQL_LOG_EVENT_TYPE::AUTH_CLOSE:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PGSQL_LOG_EVENT_TYPE::ADMIN_AUTH_CLOSE;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PGSQL_LOG_EVENT_TYPE::SQLITE_AUTH_CLOSE;
					default:
						break;
				}
				break;
			default:
				break;
		}
	}

	uint64_t curtime_real=realtime_time();
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);

	char *un = (char *)"";
	char *sn = (char *)"";
	if (ui) {
		if (ui->username) {
			un = ui->username;
		}
		if (ui->dbname) {
			sn = ui->dbname;
		}
	}
	PgSQL_Event me(_et, sess->thread_session_id,
		un, sn, 
		curtime_real, 0, 0,
		ca, cl
	);
/*
	char *c=(char *)sess->CurrentQuery.QueryPointer;
	if (c) {
		me.set_query(c,sess->CurrentQuery.QueryLength);
	} else {
		me.set_query("",0);
	}
*/
	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);

	if (xi) {
		me.set_extra_info(xi);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();

	//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
        GloPgSQL_Logger->wrlock();
	me.write(audit.logfile, sess);


	unsigned long curpos=audit.logfile->tellp();
	if (curpos > audit.max_log_file_size) {
		audit_flush_log_unlocked();
	}
	wrunlock();

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void PgSQL_Logger::flush() {
	wrlock();
	if (events.logfile) {
		events.logfile->flush();
	}
	if (audit.logfile) {
		audit.logfile->flush();
	}
	wrunlock();
}

unsigned int PgSQL_Logger::events_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(events.base_filename);
	if (events.base_filename[0] == '/') {
		eval_pathname = strdup(events.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(events.datadir);
		eval_filename = strdup(events.base_filename);
		eval_dirname = strdup(events.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (events.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}

unsigned int PgSQL_Logger::audit_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(audit.base_filename);
	if (audit.base_filename[0] == '/') {
		eval_pathname = strdup(audit.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(audit.datadir);
		eval_filename = strdup(audit.base_filename);
		eval_dirname = strdup(audit.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (audit.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}

void PgSQL_Logger::print_version() {
  fprintf(stderr,"Standard ProxySQL PgSQL Logger rev. %s -- %s -- %s\n", PROXYSQL_PGSQL_LOGGER_VERSION, __FILE__, __TIMESTAMP__);
}

