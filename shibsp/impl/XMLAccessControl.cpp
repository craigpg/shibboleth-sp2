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
 * XMLAccessControl.cpp
 *
 * XML-based access control syntax
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "SessionCache.h"
#include "SPRequest.h"
#include "attribute/Attribute.h"

#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

#ifndef HAVE_STRCASECMP
# define strcasecmp _stricmp
#endif

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace {
    
    class Rule : public AccessControl
    {
    public:
        Rule(const DOMElement* e);
        ~Rule() {}

        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;
    
    private:
        string m_alias;
        vector <string> m_vals;
    };
    
    class RuleRegex : public AccessControl
    {
    public:
        RuleRegex(const DOMElement* e);
        ~RuleRegex() {
            delete m_re;
        }
        
        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;
        
    private:
        string m_alias;
        auto_arrayptr<char> m_exp;
        RegularExpression* m_re;
    };
    
    class Operator : public AccessControl
    {
    public:
        Operator(const DOMElement* e);
        ~Operator();

        Lockable* lock() {return this;}
        void unlock() {}

        aclresult_t authorized(const SPRequest& request, const Session* session) const;
        
    private:
        enum operator_t { OP_NOT, OP_AND, OP_OR } m_op;
        vector<AccessControl*> m_operands;
    };

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class XMLAccessControl : public AccessControl, public ReloadableXMLFile
    {
    public:
        XMLAccessControl(const DOMElement* e)
                : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AccessControl")), m_rootAuthz(NULL) {
            load(); // guarantees an exception or the policy is loaded
        }
        
        ~XMLAccessControl() {
            delete m_rootAuthz;
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    protected:
        pair<bool,DOMElement*> load();

    private:
        AccessControl* m_rootAuthz;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(const DOMElement* const & e)
    {
        return new XMLAccessControl(e);
    }

    static const XMLCh _AccessControl[] =   UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh ignoreCase[] =       UNICODE_LITERAL_10(i,g,n,o,r,e,C,a,s,e);
    static const XMLCh ignoreOption[] =     UNICODE_LITERAL_1(i);
    static const XMLCh _list[] =            UNICODE_LITERAL_4(l,i,s,t);
    static const XMLCh require[] =          UNICODE_LITERAL_7(r,e,q,u,i,r,e);
    static const XMLCh NOT[] =              UNICODE_LITERAL_3(N,O,T);
    static const XMLCh AND[] =              UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =               UNICODE_LITERAL_2(O,R);
    static const XMLCh _Rule[] =            UNICODE_LITERAL_4(R,u,l,e);
    static const XMLCh _RuleRegex[] =       UNICODE_LITERAL_9(R,u,l,e,R,e,g,e,x);
}

void SHIBSP_API shibsp::registerAccessControls()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.AccessControlManager.registerFactory(XML_ACCESS_CONTROL, XMLAccessControlFactory);
    conf.AccessControlManager.registerFactory("edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl", XMLAccessControlFactory);
}

Rule::Rule(const DOMElement* e)
{
    auto_ptr_char req(e->getAttributeNS(NULL,require));
    if (!req.get() || !*req.get())
        throw ConfigurationException("Access control rule missing require attribute");
    m_alias=req.get();

    auto_arrayptr<char> vals(toUTF8(e->hasChildNodes() ? e->getFirstChild()->getNodeValue() : NULL));
    if (!vals.get())
        return;
    
    const XMLCh* flag = e->getAttributeNS(NULL,_list);
    if (flag && (*flag == chLatin_f || *flag == chDigit_0)) {
        if (*vals.get())
            m_vals.push_back(vals.get());
        return;
    }
    
#ifdef HAVE_STRTOK_R
    char* pos=NULL;
    const char* token=strtok_r(const_cast<char*>(vals.get())," ",&pos);
#else
    const char* token=strtok(const_cast<char*>(vals.get())," ");
#endif
    while (token) {
        m_vals.push_back(token);
#ifdef HAVE_STRTOK_R
        token=strtok_r(NULL," ",&pos);
#else
        token=strtok(NULL," ");
#endif
    }
}

AccessControl::aclresult_t Rule::authorized(const SPRequest& request, const Session* session) const
{
    // We can make this more complex later using pluggable comparison functions,
    // but for now, just a straight port to the new Attribute API.

    // Map alias in rule to the attribute.
    if (!session) {
        request.log(SPRequest::SPWarn, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }
    
    if (m_alias == "valid-user") {
        if (session) {
            request.log(SPRequest::SPDebug,"AccessControl plugin accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }
    if (m_alias == "user") {
        for (vector<string>::const_iterator i=m_vals.begin(); i!=m_vals.end(); ++i) {
            if (*i == request.getRemoteUser()) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting REMOTE_USER (") + *i + "), authz granted");
                return shib_acl_true;
            }
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextClassRef") {
        const char* ref = session->getAuthnContextClassRef();
        for (vector<string>::const_iterator i=m_vals.begin(); ref && i!=m_vals.end(); ++i) {
            if (!strcmp(i->c_str(),ref)) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextClassRef (") + *i + "), authz granted");
                return shib_acl_true;
            }
        }
        return shib_acl_false;
    }
    else if (m_alias == "authnContextDeclRef") {
        const char* ref = session->getAuthnContextDeclRef();
        for (vector<string>::const_iterator i=m_vals.begin(); ref && i!=m_vals.end(); ++i) {
            if (!strcmp(i->c_str(),ref)) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextDeclRef (") + *i + "), authz granted");
                return shib_acl_true;
            }
        }
        return shib_acl_false;
    }

    // Find the attribute(s) matching the require rule.
    pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> attrs =
        session->getIndexedAttributes().equal_range(m_alias);
    if (attrs.first == attrs.second) {
        request.log(SPRequest::SPWarn, string("rule requires attribute (") + m_alias + "), not found in session");
        return shib_acl_false;
    }

    for (; attrs.first != attrs.second; ++attrs.first) {
        bool caseSensitive = attrs.first->second->isCaseSensitive();

        // Now we have to intersect the attribute's values against the rule's list.
        const vector<string>& vals = attrs.first->second->getSerializedValues();
        for (vector<string>::const_iterator i=m_vals.begin(); i!=m_vals.end(); ++i) {
            for (vector<string>::const_iterator j=vals.begin(); j!=vals.end(); ++j) {
                if ((caseSensitive && *i == *j) || (!caseSensitive && !strcasecmp(i->c_str(),j->c_str()))) {
                    request.log(SPRequest::SPDebug, string("AccessControl plugin expecting (") + *j + "), authz granted");
                    return shib_acl_true;
                }
            }
        }
    }

    return shib_acl_false;
}

RuleRegex::RuleRegex(const DOMElement* e) : m_exp(toUTF8(e->hasChildNodes() ? e->getFirstChild()->getNodeValue() : NULL))
{
    auto_ptr_char req(e->getAttributeNS(NULL,require));
    if (!req.get() || !*req.get() || !m_exp.get() || !*m_exp.get())
        throw ConfigurationException("Access control rule missing require attribute or element content.");
    m_alias=req.get();
    
    const XMLCh* flag = e->getAttributeNS(NULL,ignoreCase);
    bool ignore = (flag && (*flag == chLatin_t || *flag == chDigit_1));
    try {
        m_re = new RegularExpression(e->getFirstChild()->getNodeValue(), (ignore ? ignoreOption : &chNull)); 
    }
    catch (XMLException& ex) {
        auto_ptr_char tmp(ex.getMessage());
        throw ConfigurationException("Caught exception while parsing RuleRegex regular expression: $1", params(1,tmp.get()));
    }
}

AccessControl::aclresult_t RuleRegex::authorized(const SPRequest& request, const Session* session) const
{
    // Map alias in rule to the attribute.
    if (!session) {
        request.log(SPRequest::SPWarn, "AccessControl plugin not given a valid session to evaluate, are you using lazy sessions?");
        return shib_acl_false;
    }
    
    if (m_alias == "valid-user") {
        if (session) {
            request.log(SPRequest::SPDebug,"AccessControl plugin accepting valid-user based on active session");
            return shib_acl_true;
        }
        return shib_acl_false;
    }

    try {
        if (m_alias == "user") {
            if (m_re->matches(request.getRemoteUser().c_str())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting REMOTE_USER (") + m_exp.get() + "), authz granted");
                return shib_acl_true;
            }
            return shib_acl_false;
        }
        else if (m_alias == "authnContextClassRef") {
            if (session->getAuthnContextClassRef() && m_re->matches(session->getAuthnContextClassRef())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextClassRef (") + m_exp.get() + "), authz granted");
                return shib_acl_true;
            }
            return shib_acl_false;
        }
        else if (m_alias == "authnContextDeclRef") {
            if (session->getAuthnContextDeclRef() && m_re->matches(session->getAuthnContextDeclRef())) {
                request.log(SPRequest::SPDebug, string("AccessControl plugin expecting authnContextDeclRef (") + m_exp.get() + "), authz granted");
                return shib_acl_true;
            }
            return shib_acl_false;
        }

        // Find the attribute(s) matching the require rule.
        pair<multimap<string,const Attribute*>::const_iterator, multimap<string,const Attribute*>::const_iterator> attrs =
            session->getIndexedAttributes().equal_range(m_alias);
        if (attrs.first == attrs.second) {
            request.log(SPRequest::SPWarn, string("rule requires attribute (") + m_alias + "), not found in session");
            return shib_acl_false;
        }

        for (; attrs.first != attrs.second; ++attrs.first) {
            // Now we have to intersect the attribute's values against the regular expression.
            const vector<string>& vals = attrs.first->second->getSerializedValues();
            for (vector<string>::const_iterator j=vals.begin(); j!=vals.end(); ++j) {
                if (m_re->matches(j->c_str())) {
                    request.log(SPRequest::SPDebug, string("AccessControl plugin expecting (") + m_exp.get() + "), authz granted");
                    return shib_acl_true;
                }
            }
        }
    }
    catch (XMLException& ex) {
        auto_ptr_char tmp(ex.getMessage());
        request.log(SPRequest::SPError, string("caught exception while parsing RuleRegex regular expression: ") + tmp.get());
    }
    
    return shib_acl_false;
}

Operator::Operator(const DOMElement* e)
{
    if (XMLString::equals(e->getLocalName(),NOT))
        m_op=OP_NOT;
    else if (XMLString::equals(e->getLocalName(),AND))
        m_op=OP_AND;
    else if (XMLString::equals(e->getLocalName(),OR))
        m_op=OP_OR;
    else
        throw ConfigurationException("Unrecognized operator in access control rule");
    
    try {
        e=XMLHelper::getFirstChildElement(e);
        if (XMLString::equals(e->getLocalName(),_Rule))
            m_operands.push_back(new Rule(e));
        else if (XMLString::equals(e->getLocalName(),_RuleRegex))
            m_operands.push_back(new RuleRegex(e));
        else
            m_operands.push_back(new Operator(e));
        
        if (m_op==OP_NOT)
            return;
        
        e=XMLHelper::getNextSiblingElement(e);
        while (e) {
            if (XMLString::equals(e->getLocalName(),_Rule))
                m_operands.push_back(new Rule(e));
            else if (XMLString::equals(e->getLocalName(),_RuleRegex))
                m_operands.push_back(new RuleRegex(e));
            else
                m_operands.push_back(new Operator(e));
            e=XMLHelper::getNextSiblingElement(e);
        }
    }
    catch (exception&) {
        for_each(m_operands.begin(),m_operands.end(),xmltooling::cleanup<AccessControl>());
        throw;
    }
}

Operator::~Operator()
{
    for_each(m_operands.begin(),m_operands.end(),xmltooling::cleanup<AccessControl>());
}

AccessControl::aclresult_t Operator::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_NOT:
            switch (m_operands.front()->authorized(request,session)) {
                case shib_acl_true:
                    return shib_acl_false;
                case shib_acl_false:
                    return shib_acl_true;
                default:
                    return shib_acl_indeterminate;
            }
        
        case OP_AND:
        {
            for (vector<AccessControl*>::const_iterator i=m_operands.begin(); i!=m_operands.end(); i++) {
                if ((*i)->authorized(request,session) != shib_acl_true)
                    return shib_acl_false;
            }
            return shib_acl_true;
        }
        
        case OP_OR:
        {
            for (vector<AccessControl*>::const_iterator i=m_operands.begin(); i!=m_operands.end(); i++) {
                if ((*i)->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            return shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn,"unknown operation in access control policy, denying access");
    return shib_acl_false;
}

pair<bool,DOMElement*> XMLAccessControl::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();
    
    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    // Check for AccessControl wrapper and drop a level.
    if (XMLString::equals(raw.second->getLocalName(),_AccessControl))
        raw.second = XMLHelper::getFirstChildElement(raw.second);
    
    AccessControl* authz;
    if (XMLString::equals(raw.second->getLocalName(),_Rule))
        authz=new Rule(raw.second);
    else if (XMLString::equals(raw.second->getLocalName(),_RuleRegex))
        authz=new RuleRegex(raw.second);
    else
        authz=new Operator(raw.second);

    delete m_rootAuthz;
    m_rootAuthz = authz;
    return make_pair(false,(DOMElement*)NULL);
}

AccessControl::aclresult_t XMLAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    return m_rootAuthz ? m_rootAuthz->authorized(request,session) : shib_acl_false;
}
