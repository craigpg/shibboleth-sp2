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
 * ChainingLogoutInitiator.cpp
 * 
 * Chains together multiple LogoutInitiator handlers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "handler/AbstractHandler.h"
#include "handler/LogoutHandler.h"
#include "util/SPConstants.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL ChainingLogoutInitiator : public AbstractHandler, public LogoutHandler
    {
    public:
        ChainingLogoutInitiator(const DOMElement* e, const char* appId);
        virtual ~ChainingLogoutInitiator() {
            for_each(m_handlers.begin(), m_handlers.end(), xmltooling::cleanup<Handler>());
        }
        
        pair<bool,long> run(SPRequest& request, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        const char* getType() const {
            return "LogoutInitiator";
        }

        void generateMetadata(opensaml::saml2md::SPSSODescriptor& role, const char* handlerURL) const {
            for (vector<Handler*>::const_iterator i = m_handlers.begin(); i!=m_handlers.end(); ++i)
                (*i)->generateMetadata(role, handlerURL);
        }
#endif

    private:
        vector<Handler*> m_handlers;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh _LogoutInitiator[] =     UNICODE_LITERAL_15(L,o,g,o,u,t,I,n,i,t,i,a,t,o,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    class SHIBSP_DLLLOCAL LogoutInitiatorNodeFilter : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            if (XMLHelper::isNodeNamed(node,shibspconstants::SHIB2SPCONFIG_NS,_LogoutInitiator))
                return FILTER_REJECT;
            return FILTER_ACCEPT;
        }
    };

    static SHIBSP_DLLLOCAL LogoutInitiatorNodeFilter g_LINFilter;

    Handler* SHIBSP_DLLLOCAL ChainingLogoutInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ChainingLogoutInitiator(p.first, p.second);
    }
};

ChainingLogoutInitiator::ChainingLogoutInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".LogoutInitiator.Chaining"), &g_LINFilter)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _LogoutInitiator) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_handlers.push_back(conf.LogoutInitiatorManager.newPlugin(type.get(),make_pair(e, appId)));
                m_handlers.back()->setParent(this);
            }
            catch (exception& ex) {
                m_log.error("caught exception processing embedded LogoutInitiator element: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _LogoutInitiator);
    }
}

pair<bool,long> ChainingLogoutInitiator::run(SPRequest& request, bool isHandler) const
{
    // Defer to base class first.
    pair<bool,long> ret = LogoutHandler::run(request, isHandler);
    if (ret.first)
        return ret;

    for (vector<Handler*>::const_iterator i = m_handlers.begin(); i!=m_handlers.end(); ++i) {
        ret = (*i)->run(request, isHandler);
        if (ret.first)
            return ret;
    }
    throw ConfigurationException("None of the configured LogoutInitiators handled the request.");
}
