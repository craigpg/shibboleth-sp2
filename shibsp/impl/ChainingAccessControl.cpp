/*
 *  Copyright 2009 Internet2
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
 * ChainingAccessControl.cpp
 *
 * Access control plugin that combines other plugins.
 */

#include "internal.h"
#include "exceptions.h"
#include "AccessControl.h"
#include "SessionCache.h"
#include "SPRequest.h"

#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class ChainingAccessControl : public AccessControl
    {
    public:
        ChainingAccessControl(const DOMElement* e);

        ~ChainingAccessControl() {
            for_each(m_ac.begin(), m_ac.end(), xmltooling::cleanup<AccessControl>());
        }

        Lockable* lock() {
            for_each(m_ac.begin(), m_ac.end(), mem_fun<Lockable*,Lockable>(&Lockable::lock));
            return this;
        }
        void unlock() {
            for_each(m_ac.begin(), m_ac.end(), mem_fun<void,Lockable>(&Lockable::unlock));
        }

        aclresult_t authorized(const SPRequest& request, const Session* session) const;

    private:
        enum operator_t { OP_AND, OP_OR } m_op;
        vector<AccessControl*> m_ac;
    };

    AccessControl* SHIBSP_DLLLOCAL ChainingAccessControlFactory(const DOMElement* const & e)
    {
        return new ChainingAccessControl(e);
    }

    static const XMLCh _AccessControl[] =   UNICODE_LITERAL_13(A,c,c,e,s,s,C,o,n,t,r,o,l);
    static const XMLCh _operator[] =        UNICODE_LITERAL_8(o,p,e,r,a,t,o,r);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);
    static const XMLCh AND[] =              UNICODE_LITERAL_3(A,N,D);
    static const XMLCh OR[] =               UNICODE_LITERAL_2(O,R);

    extern AccessControl* SHIBSP_DLLLOCAL XMLAccessControlFactory(const DOMElement* const & e);
}

void SHIBSP_API shibsp::registerAccessControls()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.AccessControlManager.registerFactory(CHAINING_ACCESS_CONTROL, ChainingAccessControlFactory);
    conf.AccessControlManager.registerFactory(XML_ACCESS_CONTROL, XMLAccessControlFactory);
    conf.AccessControlManager.registerFactory("edu.internet2.middleware.shibboleth.sp.provider.XMLAccessControl", XMLAccessControlFactory);
}

ChainingAccessControl::ChainingAccessControl(const DOMElement* e)
{
    const XMLCh* op = e ? e->getAttributeNS(NULL, _operator) : NULL;
    if (XMLString::equals(op, AND))
        m_op=OP_AND;
    else if (XMLString::equals(op, OR))
        m_op=OP_OR;
    else
        throw ConfigurationException("Missing or unrecognized operator in Chaining AccessControl configuration.");

    try {
        e = e ? XMLHelper::getFirstChildElement(e, _AccessControl) : NULL;
        while (e) {
            auto_ptr_char type(e->getAttributeNS(NULL, _type));
            if (type.get() && *type.get()) {
                Category::getInstance(SHIBSP_LOGCAT".AccessControl.Chaining").info("building AccessControl provider of type (%s)...", type.get());
                m_ac.push_back(SPConfig::getConfig().AccessControlManager.newPlugin(type.get(), e));
            }
            e = XMLHelper::getNextSiblingElement(e, _AccessControl);
        }
    }
    catch (exception&) {
        for_each(m_ac.begin(), m_ac.end(), xmltooling::cleanup<AccessControl>());
        throw;
    }
    if (m_ac.empty())
        throw ConfigurationException("Chaining AccessControl plugin requires at least one child plugin.");
}

AccessControl::aclresult_t ChainingAccessControl::authorized(const SPRequest& request, const Session* session) const
{
    switch (m_op) {
        case OP_AND:
        {
            for (vector<AccessControl*>::const_iterator i=m_ac.begin(); i!=m_ac.end(); ++i) {
                if ((*i)->authorized(request, session) != shib_acl_true)
                    return shib_acl_false;
            }
            return shib_acl_true;
        }

        case OP_OR:
        {
            for (vector<AccessControl*>::const_iterator i=m_ac.begin(); i!=m_ac.end(); ++i) {
                if ((*i)->authorized(request,session) == shib_acl_true)
                    return shib_acl_true;
            }
            return shib_acl_false;
        }
    }
    request.log(SPRequest::SPWarn, "unknown operation in access control policy, denying access");
    return shib_acl_false;
}
