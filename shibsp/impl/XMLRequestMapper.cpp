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

/** XMLRequestMapper.cpp
 * 
 * XML-based RequestMapper implementation
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "RequestMapper.h"
#include "SPRequest.h"
#include "util/DOMPropertySet.h"
#include "util/SPConstants.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    // Blocks access when an ACL plugin fails to load. 
    class AccessControlDummy : public AccessControl
    {
    public:
        Lockable* lock() {
            return this;
        }
        
        void unlock() {}
    
        aclresult_t authorized(const SPRequest& request, const Session* session) const {
            return shib_acl_false;
        }
    };

    class Override : public DOMPropertySet, public DOMNodeFilter
    {
    public:
        Override() : m_acl(NULL) {}
        Override(const DOMElement* e, Category& log, const Override* base=NULL);
        ~Override();

        // Provides filter to exclude special config elements.
        short acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }

        const Override* locate(const HTTPRequest& request) const;
        AccessControl* getAC() const { return (m_acl ? m_acl : (getParent() ? dynamic_cast<const Override*>(getParent())->getAC() : NULL)); }
        
    protected:
        void loadACL(const DOMElement* e, Category& log);
        
        map<string,Override*> m_map;
        vector< pair<RegularExpression*,Override*> > m_regexps;
        vector< pair< pair<string,RegularExpression*>,Override*> > m_queries;
    
    private:
        AccessControl* m_acl;
    };

    class XMLRequestMapperImpl : public Override
    {
    public:
        XMLRequestMapperImpl(const DOMElement* e, Category& log);

        ~XMLRequestMapperImpl() {
            if (m_document)
                m_document->release();
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }
    
        const Override* findOverride(const char* vhost, const HTTPRequest& request) const;

    private:    
        map<string,Override*> m_extras;
        DOMDocument* m_document;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLRequestMapper : public RequestMapper, public ReloadableXMLFile
    {
    public:
        XMLRequestMapper(const DOMElement* e) : ReloadableXMLFile(e,Category::getInstance(SHIBSP_LOGCAT".RequestMapper")), m_impl(NULL) {
            load();
        }

        ~XMLRequestMapper() {
            delete m_impl;
        }

        Settings getSettings(const HTTPRequest& request) const;

    protected:
        pair<bool,DOMElement*> load();

    private:
        XMLRequestMapperImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    RequestMapper* SHIBSP_DLLLOCAL XMLRequestMapperFactory(const DOMElement* const & e)
    {
        return new XMLRequestMapper(e);
    }

    static const XMLCh _AccessControl[] =           UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh AccessControlProvider[] =    UNICODE_LITERAL_21(A,c,c,e,s,s,C,o,n,t,r,o,l,P,r,o,v,i,d,e,r);
    static const XMLCh Host[] =                     UNICODE_LITERAL_4(H,o,s,t);
    static const XMLCh HostRegex[] =                UNICODE_LITERAL_9(H,o,s,t,R,e,g,e,x);
    static const XMLCh htaccess[] =                 UNICODE_LITERAL_8(h,t,a,c,c,e,s,s);
    static const XMLCh ignoreCase[] =               UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh ignoreOption[] =             UNICODE_LITERAL_1(i);
    static const XMLCh Path[] =                     UNICODE_LITERAL_4(P,a,t,h);
    static const XMLCh PathRegex[] =                UNICODE_LITERAL_9(P,a,t,h,R,e,g,e,x);
    static const XMLCh Query[] =                    UNICODE_LITERAL_5(Q,u,e,r,y);
    static const XMLCh name[] =                     UNICODE_LITERAL_4(n,a,m,e);
    static const XMLCh regex[] =                    UNICODE_LITERAL_5(r,e,g,e,x);
    static const XMLCh _type[] =                    UNICODE_LITERAL_4(t,y,p,e);
}

void SHIBSP_API shibsp::registerRequestMappers()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.RequestMapperManager.registerFactory(XML_REQUEST_MAPPER, XMLRequestMapperFactory);
    conf.RequestMapperManager.registerFactory(NATIVE_REQUEST_MAPPER, XMLRequestMapperFactory);
}

void Override::loadACL(const DOMElement* e, Category& log)
{
    try {
        const DOMElement* acl=XMLHelper::getFirstChildElement(e,htaccess);
        if (acl) {
            log.info("building Apache htaccess AccessControl provider...");
            m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(HT_ACCESS_CONTROL,acl);
        }
        else {
            acl=XMLHelper::getFirstChildElement(e,_AccessControl);
            if (acl) {
                log.info("building XML-based AccessControl provider...");
                m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(XML_ACCESS_CONTROL,acl);
            }
            else {
                acl=XMLHelper::getFirstChildElement(e,AccessControlProvider);
                if (acl) {
                    auto_ptr_char type(acl->getAttributeNS(NULL,_type));
                    log.info("building AccessControl provider of type %s...",type.get());
                    m_acl=SPConfig::getConfig().AccessControlManager.newPlugin(type.get(),acl);
                }
            }
        }
    }
    catch (exception& ex) {
        log.crit("exception building AccessControl provider: %s", ex.what());
        m_acl = new AccessControlDummy();
    }
}

Override::Override(const DOMElement* e, Category& log, const Override* base) : m_acl(NULL)
{
    try {
        // Load the property set.
        load(e,NULL,this);
        setParent(base);
        
        // Load any AccessControl provider.
        loadACL(e,log);
    
        // Handle nested Paths.
        DOMElement* path = XMLHelper::getFirstChildElement(e,Path);
        for (int i=1; path; ++i, path=XMLHelper::getNextSiblingElement(path,Path)) {
            const XMLCh* n=path->getAttributeNS(NULL,name);
            
            // Skip any leading slashes.
            while (n && *n==chForwardSlash)
                n++;
            
            // Check for empty name.
            if (!n || !*n) {
                log.warn("skipping Path element (%d) with empty name attribute", i);
                continue;
            }

            // Check for an embedded slash.
            int slash=XMLString::indexOf(n,chForwardSlash);
            if (slash>0) {
                // Copy the first path segment.
                XMLCh* namebuf=new XMLCh[slash + 1];
                for (int pos=0; pos < slash; pos++)
                    namebuf[pos]=n[pos];
                namebuf[slash]=chNull;
                
                // Move past the slash in the original pathname.
                n=n+slash+1;
                
                // Skip any leading slashes again.
                while (*n==chForwardSlash)
                    n++;
                
                if (*n) {
                    // Create a placeholder Path element for the first path segment and replant under it.
                    DOMElement* newpath=path->getOwnerDocument()->createElementNS(shibspconstants::SHIB2SPCONFIG_NS,Path);
                    newpath->setAttributeNS(NULL,name,namebuf);
                    path->setAttributeNS(NULL,name,n);
                    path->getParentNode()->replaceChild(newpath,path);
                    newpath->appendChild(path);
                    
                    // Repoint our locals at the new parent.
                    path=newpath;
                    n=path->getAttributeNS(NULL,name);
                }
                else {
                    // All we had was a pathname with trailing slash(es), so just reset it without them.
                    path->setAttributeNS(NULL,name,namebuf);
                    n=path->getAttributeNS(NULL,name);
                }
                delete[] namebuf;
            }
            
            Override* o=new Override(path,log,this);
            pair<bool,const char*> name=o->getString("name");
            char* dup=strdup(name.second);
            for (char* pch=dup; *pch; pch++)
                *pch=tolower(*pch);
            if (m_map.count(dup)) {
                log.warn("skipping duplicate Path element (%s)",dup);
                free(dup);
                delete o;
                continue;
            }
            m_map[dup]=o;
            log.debug("added Path mapping (%s)", dup);
            free(dup);
        }

        if (!XMLString::equals(e->getLocalName(), PathRegex)) {
            // Handle nested PathRegexs.
            path = XMLHelper::getFirstChildElement(e,PathRegex);
            for (int i=1; path; ++i, path=XMLHelper::getNextSiblingElement(path,PathRegex)) {
                const XMLCh* n=path->getAttributeNS(NULL,regex);
                if (!n || !*n) {
                    log.warn("skipping PathRegex element (%d) with empty regex attribute",i);
                    continue;
                }

                auto_ptr<Override> o(new Override(path,log,this));

                const XMLCh* flag=path->getAttributeNS(NULL,ignoreCase);
                try {
                    auto_ptr<RegularExpression> re(
                        new RegularExpression(n, (flag && (*flag==chLatin_f || *flag==chDigit_0)) ? &chNull : ignoreOption)
                        );
                    m_regexps.push_back(make_pair(re.release(), o.release()));
                }
                catch (XMLException& ex) {
                    auto_ptr_char tmp(ex.getMessage());
                    log.error("caught exception while parsing PathRegex regular expression (%d): %s", i, tmp.get());
                    throw ConfigurationException("Invalid regular expression in PathRegex element.");
                }

                if (log.isDebugEnabled())
                    log.debug("added <PathRegex> mapping (%s)", m_regexps.back().second->getString("regex").second);
            }
        }

        // Handle nested Querys.
        path = XMLHelper::getFirstChildElement(e,Query);
        for (int i=1; path; ++i, path=XMLHelper::getNextSiblingElement(path,Query)) {
            const XMLCh* n=path->getAttributeNS(NULL,name);
            if (!n || !*n) {
                log.warn("skipping Query element (%d) with empty name attribute",i);
                continue;
            }
            auto_ptr_char ntemp(n);
            const XMLCh* v=path->getAttributeNS(NULL,regex);

            auto_ptr<Override> o(new Override(path,log,this));
            try {
                RegularExpression* re = NULL;
                if (v && *v)
                    re = new RegularExpression(v);
                m_queries.push_back(make_pair(make_pair(string(ntemp.get()),re), o.release()));
            }
            catch (XMLException& ex) {
                auto_ptr_char tmp(ex.getMessage());
                log.error("caught exception while parsing Query regular expression (%d): %s", i, tmp.get());
                throw ConfigurationException("Invalid regular expression in Query element.");
            }
            
            log.debug("added <Query> mapping (%s)", ntemp.get());
        }
    }
    catch (exception&) {
        delete m_acl;
        for_each(m_map.begin(),m_map.end(),xmltooling::cleanup_pair<string,Override>());
        for (vector< pair<RegularExpression*,Override*> >::iterator i = m_regexps.begin(); i != m_regexps.end(); ++i) {
            delete i->first;
            delete i->second;
        }
        for (vector< pair< pair<string,RegularExpression*>,Override*> >::iterator j = m_queries.begin(); j != m_queries.end(); ++j) {
            delete j->first.second;
            delete j->second;
        }
        throw;
    }
}

Override::~Override()
{
    delete m_acl;
    for_each(m_map.begin(),m_map.end(),xmltooling::cleanup_pair<string,Override>());
    for (vector< pair<RegularExpression*,Override*> >::iterator i = m_regexps.begin(); i != m_regexps.end(); ++i) {
        delete i->first;
        delete i->second;
    }
    for (vector< pair< pair<string,RegularExpression*>,Override*> >::iterator j = m_queries.begin(); j != m_queries.end(); ++j) {
        delete j->first.second;
        delete j->second;
    }
}

const Override* Override::locate(const HTTPRequest& request) const
{
    // This function is confusing because it's *not* recursive.
    // The whole path is tokenized and mapped in a loop, so the
    // path parameter starts with the entire request path and
    // we can skip the leading slash as irrelevant.
    const char* path = request.getRequestURI();
    if (*path == '/')
        path++;

    // Now we copy the path, chop the query string, and lower case it.
    char* dup=strdup(path);
    char* sep=strchr(dup,'?');
    if (sep)
        *sep=0;
    for (char* pch=dup; *pch; pch++)
        *pch=tolower(*pch);

    // Default is for the current object to provide settings.
    const Override* o=this;

    // Tokenize the path by segment and try and map each segment.
#ifdef HAVE_STRTOK_R
    char* pos=NULL;
    const char* token=strtok_r(dup,"/",&pos);
#else
    const char* token=strtok(dup,"/");
#endif
    while (token) {
        map<string,Override*>::const_iterator i=o->m_map.find(token);
        if (i==o->m_map.end())
            break;  // Once there's no match, we've consumed as much of the path as possible here.
        // We found a match, so reset the settings pointer.
        o=i->second;
        
        // We descended a step down the path, so we need to advance the original
        // parameter for the regex step later.
        path += strlen(token);
        if (*path == '/')
            path++;

        // Get the next segment, if any.
#ifdef HAVE_STRTOK_R
        token=strtok_r(NULL,"/",&pos);
#else
        token=strtok(NULL,"/");
#endif
    }

    free(dup);

    // If there's anything left, we try for a regex match on the rest of the path minus the query string.
    if (*path) {
        string path2(path);
        path2 = path2.substr(0,path2.find('?'));

        for (vector< pair<RegularExpression*,Override*> >::const_iterator re = o->m_regexps.begin(); re != o->m_regexps.end(); ++re) {
            if (re->first->matches(path2.c_str())) {
                o = re->second;
                break;
            }
        }
    }

    // Finally, check for query string matches. This is another "unrolled" recursive descent in a loop.
    bool descended;
    do {
        descended = false;
        for (vector< pair< pair<string,RegularExpression*>,Override*> >::const_iterator q = o->m_queries.begin(); !descended && q != o->m_queries.end(); ++q) {
            vector<const char*> vals;
            if (request.getParameters(q->first.first.c_str(), vals)) {
                if (q->first.second) {
                    // We have to match one of the values.
                    for (vector<const char*>::const_iterator v = vals.begin(); v != vals.end(); ++v) {
                        if (q->first.second->matches(*v)) {
                            o = q->second;
                            descended = true;
                            break;
                        }
                    }
                }
                else {
                    // The simple presence of the parameter is sufficient to match.
                    o = q->second;
                    descended = true;
                }
            }
        }
    } while (descended);

    return o;
}

XMLRequestMapperImpl::XMLRequestMapperImpl(const DOMElement* e, Category& log) : m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLRequestMapperImpl");
#endif

    // Load the property set.
    load(e,NULL,this);
    
    // Load any AccessControl provider.
    loadACL(e,log);

    // Loop over the HostRegex elements.
    const DOMElement* host = XMLHelper::getFirstChildElement(e,HostRegex);
    for (int i=1; host; ++i, host=XMLHelper::getNextSiblingElement(host,HostRegex)) {
        const XMLCh* n=host->getAttributeNS(NULL,regex);
        if (!n || !*n) {
            log.warn("Skipping HostRegex element (%d) with empty regex attribute",i);
            continue;
        }

        auto_ptr<Override> o(new Override(host,log,this));

        const XMLCh* flag=host->getAttributeNS(NULL,ignoreCase);
        try {
            auto_ptr<RegularExpression> re(
                new RegularExpression(n, (flag && (*flag==chLatin_f || *flag==chDigit_0)) ? &chNull : ignoreOption)
                );
            m_regexps.push_back(make_pair(re.release(), o.release()));
        }
        catch (XMLException& ex) {
            auto_ptr_char tmp(ex.getMessage());
            log.error("caught exception while parsing HostRegex regular expression (%d): %s", i, tmp.get());
        }

        log.debug("Added <HostRegex> mapping for %s", m_regexps.back().second->getString("regex").second);
    }

    // Loop over the Host elements.
    host = XMLHelper::getFirstChildElement(e,Host);
    for (int i=1; host; ++i, host=XMLHelper::getNextSiblingElement(host,Host)) {
        const XMLCh* n=host->getAttributeNS(NULL,name);
        if (!n || !*n) {
            log.warn("Skipping Host element (%d) with empty name attribute",i);
            continue;
        }
        
        Override* o=new Override(host,log,this);
        pair<bool,const char*> name=o->getString("name");
        pair<bool,const char*> scheme=o->getString("scheme");
        pair<bool,const char*> port=o->getString("port");
        
        char* dup=strdup(name.second);
        for (char* pch=dup; *pch; pch++)
            *pch=tolower(*pch);
        auto_ptr<char> dupwrap(dup);

        if (!scheme.first && port.first) {
            // No scheme, but a port, so assume http.
            scheme = pair<bool,const char*>(true,"http");
        }
        else if (scheme.first && !port.first) {
            // Scheme, no port, so default it.
            // XXX Use getservbyname instead?
            port.first = true;
            if (!strcmp(scheme.second,"http"))
                port.second = "80";
            else if (!strcmp(scheme.second,"https"))
                port.second = "443";
            else if (!strcmp(scheme.second,"ftp"))
                port.second = "21";
            else if (!strcmp(scheme.second,"ldap"))
                port.second = "389";
            else if (!strcmp(scheme.second,"ldaps"))
                port.second = "636";
        }

        if (scheme.first) {
            string url(scheme.second);
            url=url + "://" + dup;
            
            // Is this the default port?
            if ((!strcmp(scheme.second,"http") && !strcmp(port.second,"80")) ||
                (!strcmp(scheme.second,"https") && !strcmp(port.second,"443")) ||
                (!strcmp(scheme.second,"ftp") && !strcmp(port.second,"21")) ||
                (!strcmp(scheme.second,"ldap") && !strcmp(port.second,"389")) ||
                (!strcmp(scheme.second,"ldaps") && !strcmp(port.second,"636"))) {
                // First store a port-less version.
                if (m_map.count(url) || m_extras.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
                
                // Now append the port. We use the extras vector, to avoid double freeing the object later.
                url=url + ':' + port.second;
                m_extras[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
            else {
                url=url + ':' + port.second;
                if (m_map.count(url) || m_extras.count(url)) {
                    log.warn("Skipping duplicate Host element (%s)",url.c_str());
                    delete o;
                    continue;
                }
                m_map[url]=o;
                log.debug("Added <Host> mapping for %s",url.c_str());
            }
        }
        else {
            // No scheme or port, so we enter dual hosts on http:80 and https:443
            string url("http://");
            url = url + dup;
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                delete o;
                continue;
            }
            m_map[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = url + ":80";
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = "https://";
            url = url + dup;
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
            
            url = url + ":443";
            if (m_map.count(url) || m_extras.count(url)) {
                log.warn("Skipping duplicate Host element (%s)",url.c_str());
                continue;
            }
            m_extras[url]=o;
            log.debug("Added <Host> mapping for %s",url.c_str());
        }
    }
}

const Override* XMLRequestMapperImpl::findOverride(const char* vhost, const HTTPRequest& request) const
{
    const Override* o=NULL;
    map<string,Override*>::const_iterator i=m_map.find(vhost);
    if (i!=m_map.end())
        o=i->second;
    else {
        i=m_extras.find(vhost);
        if (i!=m_extras.end())
            o=i->second;
        else {
            for (vector< pair<RegularExpression*,Override*> >::const_iterator re = m_regexps.begin(); !o && re != m_regexps.end(); ++re) {
                if (re->first->matches(vhost))
                    o=re->second;
            }
        }
    }
    
    return o ? o->locate(request) : this;
}

pair<bool,DOMElement*> XMLRequestMapper::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLRequestMapperImpl* impl = new XMLRequestMapperImpl(raw.second,m_log);
    
    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}

RequestMapper::Settings XMLRequestMapper::getSettings(const HTTPRequest& request) const
{
    ostringstream vhost;
    vhost << request.getScheme() << "://" << request.getHostname() << ':' << request.getPort();

    const Override* o=m_impl->findOverride(vhost.str().c_str(), request);

    if (m_log.isDebugEnabled()) {
#ifdef _DEBUG
        xmltooling::NDC ndc("getSettings");
#endif
        pair<bool,const char*> ret=o->getString("applicationId");
        m_log.debug("mapped %s%s to %s", vhost.str().c_str(), request.getRequestURI() ? request.getRequestURI() : "", ret.second);
    }

    return Settings(o,o->getAC());
}
