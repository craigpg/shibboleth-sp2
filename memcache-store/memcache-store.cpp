/*
 *  Copyright 2001-2008 Internet2
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
 * memcache-store.cpp
 *
 * Storage Service using memcache (pre memcache tags)
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#include <xercesc/util/XMLUniDefs.hpp>

#include <xmltooling/logging.h>

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/NDC.h>
#include <xmltooling/util/StorageService.h>
#include <xmltooling/util/XMLHelper.h>

#include <libmemcached/memcached.h>

using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

namespace xmltooling {
  static const XMLCh Hosts[] = UNICODE_LITERAL_5(H,o,s,t,s);
  static const XMLCh prefix[] = UNICODE_LITERAL_6(p,r,e,f,i,x);
  static const XMLCh buildMap[] = UNICODE_LITERAL_8(b,u,i,l,d,M,a,p);
  
  class mc_record {
  public:
    string value;
    time_t expiration;
    mc_record(){};
    mc_record(string _v, time_t _e) :
      value(_v), expiration(_e)
    {}
  };

  class MemcacheBase {
  public:
    MemcacheBase(const DOMElement* e);
    ~MemcacheBase();
        
    bool addMemcache(const char *key,
                     string &value,
                     time_t timeout,
                     uint32_t flags,
                     bool use_prefix = true);
    bool setMemcache(const char *key,
                     string &value,
                     time_t timeout,
                     uint32_t flags,
                     bool use_prefix = true);
    bool replaceMemcache(const char *key,
                         string &value,
                         time_t timeout,
                         uint32_t flags,
                         bool use_prefix = true);
    bool getMemcache(const char *key,
                     string &dest,
                     uint32_t *flags,
                     bool use_prefix = true);
    bool deleteMemcache(const char *key,
                        time_t timeout,
                        bool use_prefix = true);

    void serialize(mc_record &source, string &dest);
    void serialize(list<string> &source, string &dest);
    void deserialize(string &source, mc_record &dest);
    void deserialize(string &source, list<string> &dest);

    bool addSessionToUser(string &key, string &user);
    bool addLock(string what, bool use_prefix = true);
    void deleteLock(string what, bool use_prefix = true);

  protected:
    const DOMElement* m_root; // can only use this during initialization
    Category& log;
    memcached_st *memc;
    string m_memcacheHosts;
    string m_prefix;
    
  };
  
  class MemcacheStorageService : public StorageService, public MemcacheBase {

  public:
    MemcacheStorageService(const DOMElement* e);
    ~MemcacheStorageService();
    
    bool createString(const char* context, const char* key, const char* value, time_t expiration);
    int readString(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL, int version=0);
    int updateString(const char* context, const char* key, const char* value=NULL, time_t expiration=0, int version=0);
    bool deleteString(const char* context, const char* key);
    
    bool createText(const char* context, const char* key, const char* value, time_t expiration) {
      return createString(context, key, value, expiration);
    }
    int readText(const char* context, const char* key, string* pvalue=NULL, time_t* pexpiration=NULL, int version=0) {
      return readString(context, key, pvalue, pexpiration, version);
    }
    int updateText(const char* context, const char* key, const char* value=NULL, time_t expiration=0, int version=0) {
      return updateString(context, key, value, expiration, version);
    }
    bool deleteText(const char* context, const char* key) {
      return deleteString(context, key);
    }
    
    void reap(const char* context) {}

    void updateContext(const char* context, time_t expiration);
    void deleteContext(const char* context);

    private:

    Category& m_log;
    bool m_buildMap;


  };

  StorageService* MemcacheStorageServiceFactory(const DOMElement* const & e) {
    return new MemcacheStorageService(e);
  }

};

bool MemcacheBase::addLock(string what, bool use_prefix) {
  string lock_name = what + ":LOCK";
  string set_val = "1";
  unsigned tries = 5;
  while (!addMemcache(lock_name.c_str(), set_val, 5, 0, use_prefix)) {
    if (tries-- < 0) {
      log.debug("Unable to get lock %s... FAILED.", lock_name.c_str());
      return false;
    }
    log.debug("Unable to get lock %s... Retrying.", lock_name.c_str());
    
    // sleep 100ms
    struct timeval tv = { 0, 100000 };
    select(0, 0, 0, 0, &tv);    
  }
  return true;
}

void MemcacheBase::deleteLock(string what, bool use_prefix) {

  string lock_name = what + ":LOCK";
  deleteMemcache(lock_name.c_str(), 0, use_prefix);
  return;

}  

void MemcacheBase::deserialize(string &source, mc_record &dest) {
  istringstream is(source, stringstream::in | stringstream::out);
  is >> dest.expiration;
  is.ignore(1); // ignore delimiter
  dest.value = is.str().c_str() + is.tellg();
}

void MemcacheBase::deserialize(string &source, list<string> &dest) {
  istringstream is(source, stringstream::in | stringstream::out);
  while (!is.eof()) {
    string s;
    is >> s;
    dest.push_back(s);
  }  
}

void MemcacheBase::serialize(mc_record &source, string &dest) {
  ostringstream os(stringstream::in | stringstream::out);
  os << source.expiration;
  os << "-"; // delimiter
  os << source.value;
  dest = os.str();
}

void MemcacheBase::serialize(list<string> &source, string &dest) {  
  ostringstream os(stringstream::in | stringstream::out);
  for(list<string>::iterator iter = source.begin(); iter != source.end(); iter++) {
    if (iter != source.begin()) {
      os << endl;
    }
    os << *iter;
  }
  dest = os.str();
}

bool MemcacheBase::addSessionToUser(string &key, string &user) {

  if (! addLock(user, false)) {
    return false;
  }

  // Aquired lock

  string sessid = m_prefix + key; // add specific prefix to session
  string delimiter = ";";
  string user_key = "UDATA:";
  user_key += user;
  string user_val;
  uint32_t flags;
  bool result = getMemcache(user_key.c_str(), user_val, &flags, false);

  if (result) {
    bool already_there = false;
    // skip delimiters at beginning.
    string::size_type lastPos = user_val.find_first_not_of(delimiter, 0);
    
    // find first "non-delimiter".
    string::size_type pos = user_val.find_first_of(delimiter, lastPos);
    
    while (string::npos != pos || string::npos != lastPos) {
      // found a token, add it to the vector.
      string session = user_val.substr(lastPos, pos - lastPos);
      if (strcmp(session.c_str(), sessid.c_str()) == 0) {
        already_there = true;
        break;
      }
      
      // skip delimiters.  Note the "not_of"
      lastPos = user_val.find_first_not_of(delimiter, pos);
      
      // find next "non-delimiter"
      pos = user_val.find_first_of(delimiter, lastPos);
    }
    
    if (!already_there) {
      user_val += delimiter + sessid;
      replaceMemcache(user_key.c_str(), user_val, 0, 0, false);
    }
  } else {
    addMemcache(user_key.c_str(), sessid, 0, 0, false);
  }

  deleteLock(user, false);
  return true;
  
}

bool MemcacheBase::deleteMemcache(const char *key,
                                  time_t timeout,
                                  bool use_prefix) {
  memcached_return rv;
  string final_key;
  memcached_st clone;
  bool success;

  if (use_prefix) {
    final_key = m_prefix + key;
  } else {
    final_key = key;
  }

  if (memcached_clone(&clone, memc) == NULL) {
    throw IOException("MemcacheBase::deleteMemcache(): memcached_clone() failed");
  }

  rv = memcached_delete(&clone, (char *)final_key.c_str(), final_key.length(), timeout);
  if (rv == MEMCACHED_SUCCESS) {
    success = true;
  } else if (rv == MEMCACHED_NOTFOUND) {
    // Key wasn't there... No biggie.
    success = false;
  } else {
    log.error(string("Memcache::deleteMemcache() Problems: ") + memcached_strerror(&clone, rv));
    // shouldn't be here
    success = false;
  }

  memcached_free(&clone);
  return success;
}

bool MemcacheBase::getMemcache(const char *key,
                               string &dest,
                               uint32_t *flags,
                               bool use_prefix) {
  memcached_return rv;
  size_t len;
  char *result;
  string final_key;
  memcached_st clone;
  bool success;
  
  if (use_prefix) {
    final_key = m_prefix + key;
  } else {
    final_key = key;
  }

  if (memcached_clone(&clone, memc) == NULL) {
    throw IOException("MemcacheBase::getMemcache(): memcached_clone() failed");
  }

  result = memcached_get(&clone, (char *)final_key.c_str(), final_key.length(), &len, flags, &rv);
  if (rv == MEMCACHED_SUCCESS) {
    dest = result;
    free(result);
    success = true;
  } else if (rv == MEMCACHED_NOTFOUND) {
    log.debug("Key %s not found in memcache...", key);
    success = false;
  } else {
    log.error(string("Memcache::getMemcache() Problems: ") + memcached_strerror(&clone, rv));
    success = false;
  }

  memcached_free(&clone);
  return success;
}

bool MemcacheBase::addMemcache(const char *key,
                               string &value,
                               time_t timeout,
                               uint32_t flags,
                               bool use_prefix) {

  memcached_return rv;
  string final_key;
  memcached_st clone;
  bool success;

  if (use_prefix) {
    final_key = m_prefix + key;
  } else {
    final_key = key;
  }

  if (memcached_clone(&clone, memc) == NULL) {
    throw IOException("MemcacheBase::addMemcache(): memcached_clone() failed");
  }

  rv = memcached_add(&clone, (char *)final_key.c_str(), final_key.length(), (char *)value.c_str(), value.length(), timeout, flags);
  if (rv == MEMCACHED_SUCCESS) {
    success = true;
  } else if (rv == MEMCACHED_NOTSTORED) {
    // already there
    success = false;
  } else {
    // shouldn't be here
    log.error(string("Memcache::addMemcache() Problems: ") + memcached_strerror(&clone, rv));
    success = false;
  }

  memcached_free(&clone);
  return success;
}

bool MemcacheBase::setMemcache(const char *key,
                               string &value,
                               time_t timeout,
                               uint32_t flags,
                               bool use_prefix) {

  memcached_return rv;
  string final_key;
  memcached_st clone;
  bool success;

  if (use_prefix) {
    final_key = m_prefix + key;
  } else {
    final_key = key;
  }

  if (memcached_clone(&clone, memc) == NULL) {
    throw IOException("MemcacheBase::setMemcache(): memcached_clone() failed");
  }

  rv = memcached_set(&clone, (char *)final_key.c_str(), final_key.length(), (char *)value.c_str(), value.length(), timeout, flags);
  if (rv == MEMCACHED_SUCCESS) {
    success = true;
  } else {
    // shouldn't be here
    log.error(string("Memcache::setMemcache() Problems: ") + memcached_strerror(&clone, rv));
    success = false;
  }

  memcached_free(&clone);
  return success;
}

bool MemcacheBase::replaceMemcache(const char *key,
                                   string &value,
                                   time_t timeout,
                                   uint32_t flags,
                                   bool use_prefix) {
  
  memcached_return rv;
  string final_key;
  memcached_st clone;
  bool success;

  if (use_prefix) {
    final_key = m_prefix + key;
  } else {
    final_key = key;
  }

  if (memcached_clone(&clone, memc) == NULL) {
    throw IOException("MemcacheBase::replaceMemcache(): memcached_clone() failed");
  }

  rv = memcached_replace(&clone, (char *)final_key.c_str(), final_key.length(), (char *)value.c_str(), value.length(), timeout, flags);
  if (rv == MEMCACHED_SUCCESS) {
    success = true;
  } else if (rv == MEMCACHED_NOTSTORED) {
    // not there
    success = false;
  } else {
    // shouldn't be here
    log.error(string("Memcache::replaceMemcache() Problems: ") + memcached_strerror(&clone, rv));
    success = false;
  }

  memcached_free(&clone);
  return success;
}

MemcacheBase::MemcacheBase(const DOMElement* e) : m_root(e), log(Category::getInstance("XMLTooling.MemcacheBase")), m_memcacheHosts(""), m_prefix("") {

  auto_ptr_char p(e ? e->getAttributeNS(NULL,prefix) : NULL);
  if (p.get() && *p.get()) {
    log.debug("INIT: GOT key prefix: %s", p.get());
    m_prefix = p.get();
  }

  // Grab hosts from the configuration.
  e = e ? XMLHelper::getFirstChildElement(e,Hosts) : NULL;
  if (!e || !e->hasChildNodes()) {
    throw XMLToolingException("Memcache StorageService requires Hosts element in configuration.");
  }
  auto_ptr_char h(e->getFirstChild()->getNodeValue());
  log.debug("INIT: GOT Hosts: %s", h.get());
  m_memcacheHosts = h.get();

  memc = memcached_create(NULL);
  if (memc == NULL) {
    throw XMLToolingException("MemcacheBase::Memcache(): memcached_create() failed");
  }

  log.debug("Memcache created");

  unsigned int set = MEMCACHED_HASH_CRC;
  memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_HASH, set);
  log.debug("CRC hash set");

  memcached_server_st *servers;
  servers = memcached_servers_parse((char *)m_memcacheHosts.c_str());
  log.debug("Got %u hosts.",  memcached_server_list_count(servers));
  if (memcached_server_push(memc, servers) != MEMCACHED_SUCCESS) {
    throw IOException("MemcacheBase::Memcache(): memcached_server_push() failed");    
  }
  memcached_server_list_free(servers);

  log.debug("Memcache object initialized");
}

MemcacheBase::~MemcacheBase() {
  memcached_free(memc);
  log.debug("Base object destroyed");
}

MemcacheStorageService::MemcacheStorageService(const DOMElement* e)
  : MemcacheBase(e), m_log(Category::getInstance("XMLTooling.MemcacheStorageService")), m_buildMap(false) {

    const XMLCh* tag=e ? e->getAttributeNS(NULL,buildMap) : NULL;
    if (tag && *tag && XMLString::parseInt(tag) != 0) {
        m_buildMap = true;
        m_log.debug("Cache built with buildMap ON");
    }

}

MemcacheStorageService::~MemcacheStorageService() {

  
}

bool MemcacheStorageService::createString(const char* context, const char* key, const char* value, time_t expiration) {

  log.debug("createString ctx: %s - key: %s", context, key);

  string final_key = string(context) + ":" + string(key);

  mc_record rec(value, expiration);
  string final_value;
  serialize(rec, final_value);

  bool result = addMemcache(final_key.c_str(), final_value, expiration, 1); // the flag will be the version

  if (result && m_buildMap) {
    log.debug("Got result, updating map");

    string map_name = context;
    // we need to update the context map
    if (! addLock(map_name)) {
      log.error("Unable to get lock for context %s!", context);
      deleteMemcache(final_key.c_str(), 0);
      return false;
    }

    string ser_arr;
    uint32_t flags;
    bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
    
    list<string> contents;
    if (result) {
      log.debug("Match found. Parsing...");

      deserialize(ser_arr, contents);
      
      log.debug("Iterating retrieved session map...");
      list<string>::iterator iter;
      for(iter = contents.begin(); 
          iter != contents.end();
          iter++) {
        log.debug("value = " + *iter);
      }

    } else {
      log.debug("New context: %s", map_name.c_str());

    }

    contents.push_back(key);
    serialize(contents, ser_arr);    
    setMemcache(map_name.c_str(), ser_arr, expiration, 0);    
    
    deleteLock(map_name);
  }

  return result;  

}

int MemcacheStorageService::readString(const char* context, const char* key, string* pvalue, time_t* pexpiration, int version) {

  log.debug("readString ctx: %s - key: %s", context, key);

  string final_key = string(context) + ":" + string(key);
  uint32_t rec_version;
  string value;

  bool found = getMemcache(final_key.c_str(), value, &rec_version);
  if (!found) {
    return 0;
  }

  if (version && rec_version <= (uint32_t)version) {
    return version;
  }

  if (pexpiration || pvalue) {
    mc_record rec;
    deserialize(value, rec);
    
    if (pexpiration) {
      *pexpiration = rec.expiration;
    }
    
    if (pvalue) {
      *pvalue = rec.value;
    }
  }
  
  return rec_version;

}

int MemcacheStorageService::updateString(const char* context, const char* key, const char* value, time_t expiration, int version) {

  log.debug("updateString ctx: %s - key: %s", context, key);

  time_t final_exp = expiration;
  time_t *want_expiration = NULL;
  if (! final_exp) {
    want_expiration = &final_exp;
  }

  int read_res = readString(context, key, NULL, want_expiration, version);

  if (!read_res) {
    // not found
    return read_res;
  }

  if (version && version != read_res) {
    // version incorrect
    return -1;
  }

  // Proceding with update
  string final_key = string(context) + ":" + string(key);
  mc_record rec(value, final_exp);
  string final_value;
  serialize(rec, final_value);

  replaceMemcache(final_key.c_str(), final_value, final_exp, ++version);
  return version;

}

bool MemcacheStorageService::deleteString(const char* context, const char* key) {

  log.debug("deleteString ctx: %s - key: %s", context, key);
  
  string final_key = string(context) + ":" + string(key);

  // Not updating context map, if there is one. There is no need.

  return deleteMemcache(final_key.c_str(), 0);

}

void MemcacheStorageService::updateContext(const char* context, time_t expiration) {

  log.debug("updateContext ctx: %s", context);

  if (!m_buildMap) {
    log.error("updateContext invoked on a Storage with no context map built!");
    return;
  }

  string map_name = context;
  
  if (! addLock(map_name)) {
    log.error("Unable to get lock for context %s!", context);
    return;
  }
  
  string ser_arr;
  uint32_t flags;
  bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
  
  list<string> contents;
  if (result) {
    log.debug("Match found. Parsing...");
    
    deserialize(ser_arr, contents);
    
    log.debug("Iterating retrieved session map...");
    list<string>::iterator iter;
    for(iter = contents.begin(); 
        iter != contents.end();
        iter++) {

      // Update expiration times
      string value;      
      int read_res = readString(context, iter->c_str(), &value, NULL, 0);
      
      if (!read_res) {
        // not found
        continue;
      }

      updateString(context, iter->c_str(), value.c_str(), expiration, read_res);
    }
    replaceMemcache(map_name.c_str(), ser_arr, expiration, flags);
  }
  
  deleteLock(map_name);
  
}

void MemcacheStorageService::deleteContext(const char* context) {

  log.debug("deleteContext ctx: %s", context);

  if (!m_buildMap) {
    log.error("deleteContext invoked on a Storage with no context map built!");
    return;
  }

  string map_name = context;
  
  if (! addLock(map_name)) {
    log.error("Unable to get lock for context %s!", context);
    return;
  }
  
  string ser_arr;
  uint32_t flags;
  bool result = getMemcache(map_name.c_str(), ser_arr, &flags);
  
  list<string> contents;
  if (result) {
    log.debug("Match found. Parsing...");
    
    deserialize(ser_arr, contents);
    
    log.debug("Iterating retrieved session map...");
    list<string>::iterator iter;
    for(iter = contents.begin(); 
        iter != contents.end();
        iter++) {
      string final_key = map_name + *iter;
      deleteMemcache(final_key.c_str(), 0);
    }
    
    deleteMemcache(map_name.c_str(), 0);
  }
  
  deleteLock(map_name);

}

extern "C" int xmltooling_extension_init(void*) {
    // Register this SS type
    XMLToolingConfig::getConfig().StorageServiceManager.registerFactory("MEMCACHE", MemcacheStorageServiceFactory);
    return 0;
}

extern "C" void xmltooling_extension_term() {
    XMLToolingConfig::getConfig().StorageServiceManager.deregisterFactory("MEMCACHE");
}
