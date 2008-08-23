/*
 *  Copyright 2001-2007 Internet2
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * odbc-store.cpp
 *
 * Storage Service using ODBC
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#ifdef WIN32
# define ODBCSTORE_EXPORTS __declspec(dllexport)
#else
# define ODBCSTORE_EXPORTS
#endif

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/Threads.h>
#include <xmltooling/util/XMLHelper.h>

#include <sql.h>
#include <sqlext.h>

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#define PLUGIN_VER_MAJOR 1
#define PLUGIN_VER_MINOR 0

#define LONGDATA_BUFLEN 16384

#define COLSIZE_CONTEXT 255
#define COLSIZE_ID 255
#define COLSIZE_STRING_VALUE 255

#define STRING_TABLE "strings"
#define TEXT_TABLE "texts"

/* table definitions
CREATE TABLE version (
    major int NOT NULL,
    minor int NOT NULL
    )

CREATE TABLE strings (
    context varchar(255) not null,
    id varchar(255) not null,
    expires datetime not null,
    version smallint not null,
    value varchar(255) not null,
    PRIMARY KEY (context, id)
    )

CREATE TABLE texts (
    context varchar(255) not null,
    id varchar(255) not null,
    expires datetime not null,
    version smallint not null,
    value text not null,
    PRIMARY KEY (context, id)
    )
*/

namespace {
    static const XMLCh cleanupInterval[] =  UNICODE_LITERAL_15(c,l,e,a,n,u,p,I,n,t,e,r,v,a,l);
    static const XMLCh isolationLevel[] =   UNICODE_LITERAL_14(i,s,o,l,a,t,i,o,n,L,e,v,e,l);
    static const XMLCh ConnectionString[] = UNICODE_LITERAL_16(C,o,n,n,e,c,t,i,o,n,S,t,r,i,n,g);
    static const XMLCh RetryOnError[] =     UNICODE_LITERAL_12(R,e,t,r,y,O,n,E,r,r,o,r);

    // RAII for ODBC handles
    struct ODBCConn {
        ODBCConn(SQLHDBC conn) : handle(conn), autoCommit(true) {}
        ~ODBCConn() {
            SQLRETURN sr = SQL_SUCCESS;
            if (!autoCommit)
                sr = SQLSetConnectAttr(handle, SQL_ATTR_AUTOCOMMIT, (SQLPOINTER)SQL_AUTOCOMMIT_ON, NULL);
            SQLDisconnect(handle);
            SQLFreeHandle(SQL_HANDLE_DBC,handle);
            if (!SQL_SUCCEEDED(sr))
                throw IOException("Failed to commit connection and return to auto-commit mode.");
        }
        operator SQLHDBC() {return handle;}
        SQLHDBC handle;
        bool autoCommit;
    };

    class ODBCStorageService : public StorageService
    {
    public:
        ODBCStorageService(const DOMElement* e);
        virtual ~ODBCStorageService();

        bool createString(const char* context, const char* key, const char* value, time_t expiration) {
            return createRow(STRING_TABLE, context, key, value, expiration);
        }
        int readString(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL, int version=0) {
            return readRow(STRING_TABLE, context, key, pvalue, pexpiration, version, false);
        }
        int updateString(const char* context, const char* key, const char* value=NULL, time_t expiration=0, int version=0) {
            return updateRow(STRING_TABLE, context, key, value, expiration, version);
        }
        bool deleteString(const char* context, const char* key) {
            return deleteRow(STRING_TABLE, context, key);
        }

        bool createText(const char* context, const char* key, const char* value, time_t expiration) {
            return createRow(TEXT_TABLE, context, key, value, expiration);
        }
        int readText(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL, int version=0) {
            return readRow(TEXT_TABLE, context, key, pvalue, pexpiration, version, true);
        }
        int updateText(const char* context, const char* key, const char* value=NULL, time_t expiration=0, int version=0) {
            return updateRow(TEXT_TABLE, context, key, value, expiration, version);
        }
        bool deleteText(const char* context, const char* key) {
            return deleteRow(TEXT_TABLE, context, key);
        }

        void reap(const char* context) {
            reap(STRING_TABLE, context);
            reap(TEXT_TABLE, context);
        }

        void updateContext(const char* context, time_t expiration) {
            updateContext(STRING_TABLE, context, expiration);
            updateContext(TEXT_TABLE, context, expiration);
        }

        void deleteContext(const char* context) {
            deleteContext(STRING_TABLE, context);
            deleteContext(TEXT_TABLE, context);
        }
         

    private:
        bool createRow(const char *table, const char* context, const char* key, const char* value, time_t expiration);
        int readRow(const char *table, const char* context, const char* key, string* pvalue, time_t* pexpiration, int version, bool text);
        int updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration, int version);
        bool deleteRow(const char *table, const char* context, const char* key);

        void reap(const char* table, const char* context);
        void updateContext(const char* table, const char* context, time_t expiration);
        void deleteContext(const char* table, const char* context);

        SQLHDBC getHDBC();
        SQLHSTMT getHSTMT(SQLHDBC);
        pair<int,int> getVersion(SQLHDBC);
        pair<bool,bool> log_error(SQLHANDLE handle, SQLSMALLINT htype, const char* checkfor=NULL);

        static void* cleanup_fn(void*); 
        void cleanup();

        Category& m_log;
        int m_cleanupInterval;
        CondWait* shutdown_wait;
        Thread* cleanup_thread;
        bool shutdown;

        SQLHENV m_henv;
        string m_connstring;
        long m_isolation;
        vector<SQLINTEGER> m_retries;
    };

    StorageService* ODBCStorageServiceFactory(const DOMElement* const & e)
    {
        return new ODBCStorageService(e);
    }

    // convert SQL timestamp to time_t 
    time_t timeFromTimestamp(SQL_TIMESTAMP_STRUCT expires)
    {
        time_t ret;
        struct tm t;
        t.tm_sec=expires.second;
        t.tm_min=expires.minute;
        t.tm_hour=expires.hour;
        t.tm_mday=expires.day;
        t.tm_mon=expires.month-1;
        t.tm_year=expires.year-1900;
        t.tm_isdst=0;
#if defined(HAVE_TIMEGM)
        ret = timegm(&t);
#else
        ret = mktime(&t) - timezone;
#endif
        return (ret);
    }

    // conver time_t to SQL string
    void timestampFromTime(time_t t, char* ret)
    {
#ifdef HAVE_GMTIME_R
        struct tm res;
        struct tm* ptime=gmtime_r(&t,&res);
#else
        struct tm* ptime=gmtime(&t);
#endif
        strftime(ret,32,"{ts '%Y-%m-%d %H:%M:%S'}",ptime);
    }

    // make a string safe for SQL command
    // result to be free'd only if it isn't the input
    static char *makeSafeSQL(const char *src)
    {
       int ns = 0;
       int nc = 0;
       char *s;
    
       // see if any conversion needed
       for (s=(char*)src; *s; nc++,s++) if (*s=='\'') ns++;
       if (ns==0) return ((char*)src);
    
       char *safe = new char[(nc+2*ns+1)];
       for (s=safe; *src; src++) {
           if (*src=='\'') *s++ = '\'';
           *s++ = (char)*src;
       }
       *s = '\0';
       return (safe);
    }

    void freeSafeSQL(char *safe, const char *src)
    {
        if (safe!=src)
            delete[](safe);
    }
};

ODBCStorageService::ODBCStorageService(const DOMElement* e) : m_log(Category::getInstance("XMLTooling.StorageService")),
   m_cleanupInterval(900), shutdown_wait(NULL), cleanup_thread(NULL), shutdown(false), m_henv(SQL_NULL_HANDLE), m_isolation(SQL_TXN_SERIALIZABLE)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("ODBCStorageService");
#endif

    const XMLCh* tag=e ? e->getAttributeNS(NULL,cleanupInterval) : NULL;
    if (tag && *tag)
        m_cleanupInterval = XMLString::parseInt(tag);
    if (!m_cleanupInterval)
        m_cleanupInterval = 900;

    auto_ptr_char iso(e ? e->getAttributeNS(NULL,isolationLevel) : NULL);
    if (iso.get() && *iso.get()) {
        if (!strcmp(iso.get(),"SERIALIZABLE"))
            m_isolation = SQL_TXN_SERIALIZABLE;
        else if (!strcmp(iso.get(),"REPEATABLE_READ"))
            m_isolation = SQL_TXN_REPEATABLE_READ;
        else if (!strcmp(iso.get(),"READ_COMMITTED"))
            m_isolation = SQL_TXN_READ_COMMITTED;
        else if (!strcmp(iso.get(),"READ_UNCOMMITTED"))
            m_isolation = SQL_TXN_READ_UNCOMMITTED;
        else
            throw XMLToolingException("Unknown transaction isolationLevel property.");
    }

    if (m_henv == SQL_NULL_HANDLE) {
        // Enable connection pooling.
        SQLSetEnvAttr(SQL_NULL_HANDLE, SQL_ATTR_CONNECTION_POOLING, (void*)SQL_CP_ONE_PER_HENV, 0);

        // Allocate the environment.
        if (!SQL_SUCCEEDED(SQLAllocHandle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_henv)))
            throw XMLToolingException("ODBC failed to initialize.");

        // Specify ODBC 3.x
        SQLSetEnvAttr(m_henv, SQL_ATTR_ODBC_VERSION, (void*)SQL_OV_ODBC3, 0);

        m_log.info("ODBC initialized");
    }

    // Grab connection string from the configuration.
    e = e ? XMLHelper::getFirstChildElement(e,ConnectionString) : NULL;
    if (!e || !e->hasChildNodes()) {
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
        throw XMLToolingException("ODBC StorageService requires ConnectionString element in configuration.");
    }
    auto_ptr_char arg(e->getFirstChild()->getNodeValue());
    m_connstring=arg.get();

    // Connect and check version.
    ODBCConn conn(getHDBC());
    pair<int,int> v=getVersion(conn);

    // Make sure we've got the right version.
    if (v.first != PLUGIN_VER_MAJOR) {
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
        m_log.crit("unknown database version: %d.%d", v.first, v.second);
        throw XMLToolingException("Unknown database version for ODBC StorageService.");
    }

    // Load any retry errors to check.
    e = XMLHelper::getNextSiblingElement(e,RetryOnError);
    while (e) {
        if (e->hasChildNodes()) {
            m_retries.push_back(XMLString::parseInt(e->getFirstChild()->getNodeValue()));
            m_log.info("will retry operations when native ODBC error (%ld) is returned", m_retries.back());
        }
        e = XMLHelper::getNextSiblingElement(e,RetryOnError);
    }

    // Initialize the cleanup thread
    shutdown_wait = CondWait::create();
    cleanup_thread = Thread::create(&cleanup_fn, (void*)this);
}

ODBCStorageService::~ODBCStorageService()
{
    shutdown = true;
    shutdown_wait->signal();
    cleanup_thread->join(NULL);
    delete shutdown_wait;
    if (m_henv != SQL_NULL_HANDLE)
        SQLFreeHandle(SQL_HANDLE_ENV, m_henv);
}

pair<bool,bool> ODBCStorageService::log_error(SQLHANDLE handle, SQLSMALLINT htype, const char* checkfor)
{
    SQLSMALLINT	 i = 0;
    SQLINTEGER	 native;
    SQLCHAR	 state[7];
    SQLCHAR	 text[256];
    SQLSMALLINT	 len;
    SQLRETURN	 ret;

    pair<bool,bool> res = make_pair(false,false);
    do {
        ret = SQLGetDiagRec(htype, handle, ++i, state, &native, text, sizeof(text), &len);
        if (SQL_SUCCEEDED(ret)) {
            m_log.error("ODBC Error: %s:%ld:%ld:%s", state, i, native, text);
            for (vector<SQLINTEGER>::const_iterator n = m_retries.begin(); !res.first && n != m_retries.end(); ++n)
                res.first = (*n == native);
            if (checkfor && !strcmp(checkfor, (const char*)state))
                res.second = true;
        }
    } while(SQL_SUCCEEDED(ret));
    return res;
}

SQLHDBC ODBCStorageService::getHDBC()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("getHDBC");
#endif

    // Get a handle.
    SQLHDBC handle;
    SQLRETURN sr=SQLAllocHandle(SQL_HANDLE_DBC, m_henv, &handle);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to allocate connection handle");
        log_error(m_henv, SQL_HANDLE_ENV);
        throw IOException("ODBC StorageService failed to allocate a connection handle.");
    }

    sr=SQLDriverConnect(handle,NULL,(SQLCHAR*)m_connstring.c_str(),m_connstring.length(),NULL,0,NULL,SQL_DRIVER_NOPROMPT);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to connect to database");
        log_error(handle, SQL_HANDLE_DBC);
        throw IOException("ODBC StorageService failed to connect to database.");
    }

    sr = SQLSetConnectAttr(handle, SQL_ATTR_TXN_ISOLATION, (SQLPOINTER)m_isolation, NULL);
    if (!SQL_SUCCEEDED(sr))
        throw IOException("ODBC StorageService failed to set transaction isolation level.");

    return handle;
}

SQLHSTMT ODBCStorageService::getHSTMT(SQLHDBC conn)
{
    SQLHSTMT hstmt;
    SQLRETURN sr=SQLAllocHandle(SQL_HANDLE_STMT,conn,&hstmt);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to allocate statement handle");
        log_error(conn, SQL_HANDLE_DBC);
        throw IOException("ODBC StorageService failed to allocate a statement handle.");
    }
    return hstmt;
}

pair<int,int> ODBCStorageService::getVersion(SQLHDBC conn)
{
    // Grab the version number from the database.
    SQLHSTMT stmt = getHSTMT(conn);
    
    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)"SELECT major,minor FROM version", SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("failed to read version from database");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to read version from database.");
    }

    SQLINTEGER major;
    SQLINTEGER minor;
    SQLBindCol(stmt,1,SQL_C_SLONG,&major,0,NULL);
    SQLBindCol(stmt,2,SQL_C_SLONG,&minor,0,NULL);

    if ((sr=SQLFetch(stmt)) != SQL_NO_DATA)
        return pair<int,int>(major,minor);

    m_log.error("no rows returned in version query");
    throw IOException("ODBC StorageService failed to read version from database.");
}

bool ODBCStorageService::createRow(const char* table, const char* context, const char* key, const char* value, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("createRow");
#endif

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and exectute insert statement.
    //char *scontext = makeSafeSQL(context);
    //char *skey = makeSafeSQL(key);
    //char *svalue = makeSafeSQL(value);
    string q  = string("INSERT INTO ") + table + " VALUES (?,?," + timebuf + ",1,?)";

    SQLRETURN sr = SQLPrepare(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLPrepare failed (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLPrepare succeeded. SQL: %s", q.c_str());

    SQLLEN b_ind = SQL_NTS;
    sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(context), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (context = %s)", context);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (context = %s)", context);

    sr = SQLBindParam(stmt, 2, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(key), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (key = %s)", key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (key = %s)", key);

    if (strcmp(table, TEXT_TABLE)==0)
        sr = SQLBindParam(stmt, 3, SQL_C_CHAR, SQL_LONGVARCHAR, strlen(value), 0, const_cast<char*>(value), &b_ind);
    else
        sr = SQLBindParam(stmt, 3, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(value), &b_ind);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("SQLBindParam failed (value = %s)", value);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to insert record.");
    }
    m_log.debug("SQLBindParam succeeded (value = %s)", value);
    
    //freeSafeSQL(scontext, context);
    //freeSafeSQL(skey, key);
    //freeSafeSQL(svalue, value);
    //m_log.debug("SQL: %s", q.c_str());

    int attempts = 3;
    pair<bool,bool> logres;
    do {
        logres = make_pair(false,false);
        attempts--;
        sr=SQLExecute(stmt);
        if (SQL_SUCCEEDED(sr)) {
            m_log.debug("SQLExecute of insert succeeded");
            return true;
        }
        m_log.error("insert record failed (t=%s, c=%s, k=%s)", table, context, key);
        logres = log_error(stmt, SQL_HANDLE_STMT, "23000");
        if (logres.second)
            return false;   // supposedly integrity violation?
    } while (attempts && logres.first);

    throw IOException("ODBC StorageService failed to insert record.");
}

int ODBCStorageService::readRow(
    const char *table, const char* context, const char* key, string* pvalue, time_t* pexpiration, int version, bool text
    )
{
#ifdef _DEBUG
    xmltooling::NDC ndc("readRow");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and exectute select statement.
    char timebuf[32];
    timestampFromTime(time(NULL), timebuf);
    char *scontext = makeSafeSQL(context);
    char *skey = makeSafeSQL(key);
    ostringstream q;
    q << "SELECT version";
    if (pexpiration)
        q << ",expires";
    if (pvalue)
        q << ",CASE version WHEN " << version << " THEN NULL ELSE value END";
    q << " FROM " << table << " WHERE context='" << scontext << "' AND id='" << skey << "' AND expires > " << timebuf;
    freeSafeSQL(scontext, context);
    freeSafeSQL(skey, key);
    if (m_log.isDebugEnabled())
        m_log.debug("SQL: %s", q.str().c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.str().c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("error searching for (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService search failed.");
    }

    SQLSMALLINT ver;
    SQL_TIMESTAMP_STRUCT expiration;

    SQLBindCol(stmt,1,SQL_C_SSHORT,&ver,0,NULL);
    if (pexpiration)
        SQLBindCol(stmt,2,SQL_C_TYPE_TIMESTAMP,&expiration,0,NULL);

    if ((sr=SQLFetch(stmt)) == SQL_NO_DATA)
        return 0;

    if (pexpiration)
        *pexpiration = timeFromTimestamp(expiration);

    if (version == ver)
        return version; // nothing's changed, so just echo back the version

    if (pvalue) {
        SQLLEN len;
        SQLCHAR buf[LONGDATA_BUFLEN];
        while ((sr=SQLGetData(stmt,pexpiration ? 3 : 2,SQL_C_CHAR,buf,sizeof(buf),&len)) != SQL_NO_DATA) {
            if (!SQL_SUCCEEDED(sr)) {
                m_log.error("error while reading text field from result set");
                log_error(stmt, SQL_HANDLE_STMT);
                throw IOException("ODBC StorageService search failed to read data from result set.");
            }
            pvalue->append((char*)buf);
        }
    }
    
    return ver;
}

int ODBCStorageService::updateRow(const char *table, const char* context, const char* key, const char* value, time_t expiration, int version)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("updateRow");
#endif

    if (!value && !expiration)
        throw IOException("ODBC StorageService given invalid update instructions.");

    // Get statement handle. Disable auto-commit mode to wrap select + update.
    ODBCConn conn(getHDBC());
    SQLRETURN sr = SQLSetConnectAttr(conn, SQL_ATTR_AUTOCOMMIT, SQL_AUTOCOMMIT_OFF, NULL);
    if (!SQL_SUCCEEDED(sr))
        throw IOException("ODBC StorageService failed to disable auto-commit mode.");
    conn.autoCommit = false;
    SQLHSTMT stmt = getHSTMT(conn);

    // First, fetch the current version for later, which also ensures the record still exists.
    char timebuf[32];
    timestampFromTime(time(NULL), timebuf);
    char *scontext = makeSafeSQL(context);
    char *skey = makeSafeSQL(key);
    string q("SELECT version FROM ");
    q = q + table + " WHERE context='" + scontext + "' AND id='" + skey + "' AND expires > " + timebuf;

    m_log.debug("SQL: %s", q.c_str());

    sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        freeSafeSQL(scontext, context);
        freeSafeSQL(skey, key);
        m_log.error("error searching for (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService search failed.");
    }

    SQLSMALLINT ver;
    SQLBindCol(stmt,1,SQL_C_SSHORT,&ver,0,NULL);
    if ((sr=SQLFetch(stmt)) == SQL_NO_DATA) {
        freeSafeSQL(scontext, context);
        freeSafeSQL(skey, key);
        return 0;
    }

    // Check version?
    if (version > 0 && version != ver) {
        freeSafeSQL(scontext, context);
        freeSafeSQL(skey, key);
        return -1;
    }

    SQLFreeHandle(SQL_HANDLE_STMT, stmt);
    stmt = getHSTMT(conn);

    // Prepare and exectute update statement.
    q = string("UPDATE ") + table + " SET ";

    if (value)
        q = q + "value=?, version=version+1";

    if (expiration) {
        timestampFromTime(expiration, timebuf);
        if (value)
            q += ',';
        q = q + "expires = " + timebuf;
    }

    q = q + " WHERE context='" + scontext + "' AND id='" + skey + "'";
    freeSafeSQL(scontext, context);
    freeSafeSQL(skey, key);

    sr = SQLPrepare(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if (!SQL_SUCCEEDED(sr)) {
        m_log.error("update of record failed (t=%s, c=%s, k=%s", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to update record.");
    }
    m_log.debug("SQLPrepare succeeded. SQL: %s", q.c_str());

    SQLLEN b_ind = SQL_NTS;
    if (value) {
        if (strcmp(table, TEXT_TABLE)==0)
            sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_LONGVARCHAR, strlen(value), 0, const_cast<char*>(value), &b_ind);
        else
            sr = SQLBindParam(stmt, 1, SQL_C_CHAR, SQL_VARCHAR, 255, 0, const_cast<char*>(value), &b_ind);
        if (!SQL_SUCCEEDED(sr)) {
            m_log.error("SQLBindParam failed (context = %s)", context);
            log_error(stmt, SQL_HANDLE_STMT);
            throw IOException("ODBC StorageService failed to update record.");
        }
        m_log.debug("SQLBindParam succeeded (context = %s)", context);
    }

    int attempts = 3;
    pair<bool,bool> logres;
    do {
        logres = make_pair(false,false);
        attempts--;
        sr=SQLExecute(stmt);
        if (sr==SQL_NO_DATA)
            return 0;   // went missing?
        else if (SQL_SUCCEEDED(sr)) {
            m_log.debug("SQLExecute of update succeeded");
            return ver + 1;
        }

        m_log.error("update of record failed (t=%s, c=%s, k=%s", table, context, key);
        logres = log_error(stmt, SQL_HANDLE_STMT);
    } while (attempts && logres.first);

    throw IOException("ODBC StorageService failed to update record.");
}

bool ODBCStorageService::deleteRow(const char *table, const char *context, const char* key)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteRow");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    char *scontext = makeSafeSQL(context);
    char *skey = makeSafeSQL(key);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "' AND id='" + skey + "'";
    freeSafeSQL(scontext, context);
    freeSafeSQL(skey, key);
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
     if (sr==SQL_NO_DATA)
        return false;
    else if (!SQL_SUCCEEDED(sr)) {
        m_log.error("error deleting record (t=%s, c=%s, k=%s)", table, context, key);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to delete record.");
    }

    return true;
}


void ODBCStorageService::cleanup()
{
#ifdef _DEBUG
    xmltooling::NDC ndc("cleanup");
#endif

    Mutex* mutex = Mutex::create();

    mutex->lock();

    m_log.info("cleanup thread started... running every %d secs", m_cleanupInterval);

    while (!shutdown) {
        shutdown_wait->timedwait(mutex, m_cleanupInterval);
        if (shutdown)
            break;
        try {
            reap(NULL);
        }
        catch (exception& ex) {
            m_log.error("cleanup thread swallowed exception: %s", ex.what());
        }
    }

    m_log.info("cleanup thread exiting...");

    mutex->unlock();
    delete mutex;
    Thread::exit(NULL);
}

void* ODBCStorageService::cleanup_fn(void* cache_p)
{
  ODBCStorageService* cache = (ODBCStorageService*)cache_p;

#ifndef WIN32
  // First, let's block all signals
  Thread::mask_all_signals();
#endif

  // Now run the cleanup process.
  cache->cleanup();
  return NULL;
}

void ODBCStorageService::updateContext(const char *table, const char* context, time_t expiration)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("updateContext");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    char timebuf[32];
    timestampFromTime(expiration, timebuf);

    char nowbuf[32];
    timestampFromTime(time(NULL), nowbuf);

    char *scontext = makeSafeSQL(context);
    string q("UPDATE ");
    q = q + table + " SET expires = " + timebuf + " WHERE context='" + scontext + "' AND expires > " + nowbuf;
    freeSafeSQL(scontext, context);

    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr!=SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error updating records (t=%s, c=%s)", table, context ? context : "all");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to update context expiration.");
    }
}

void ODBCStorageService::reap(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("reap");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    char nowbuf[32];
    timestampFromTime(time(NULL), nowbuf);
    string q;
    if (context) {
        char *scontext = makeSafeSQL(context);
        q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "' AND expires <= " + nowbuf;
        freeSafeSQL(scontext, context);
    }
    else {
        q = string("DELETE FROM ") + table + " WHERE expires <= " + nowbuf;
    }
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr!=SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error expiring records (t=%s, c=%s)", table, context ? context : "all");
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to purge expired records.");
    }
}

void ODBCStorageService::deleteContext(const char *table, const char* context)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("deleteContext");
#endif

    // Get statement handle.
    ODBCConn conn(getHDBC());
    SQLHSTMT stmt = getHSTMT(conn);

    // Prepare and execute delete statement.
    char *scontext = makeSafeSQL(context);
    string q = string("DELETE FROM ") + table + " WHERE context='" + scontext + "'";
    freeSafeSQL(scontext, context);
    m_log.debug("SQL: %s", q.c_str());

    SQLRETURN sr=SQLExecDirect(stmt, (SQLCHAR*)q.c_str(), SQL_NTS);
    if ((sr!=SQL_NO_DATA) && !SQL_SUCCEEDED(sr)) {
        m_log.error("error deleting context (t=%s, c=%s)", table, context);
        log_error(stmt, SQL_HANDLE_STMT);
        throw IOException("ODBC StorageService failed to delete context.");
    }
}

extern "C" int ODBCSTORE_EXPORTS xmltooling_extension_init(void*)
{
    // Register this SS type
    XMLToolingConfig::getConfig().StorageServiceManager.registerFactory("ODBC", ODBCStorageServiceFactory);
    return 0;
}

extern "C" void ODBCSTORE_EXPORTS xmltooling_extension_term()
{
    XMLToolingConfig::getConfig().StorageServiceManager.deregisterFactory("ODBC");
}
