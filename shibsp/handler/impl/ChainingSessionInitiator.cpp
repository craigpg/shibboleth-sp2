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
 * ChainingSessionInitiator.cpp
 * 
 * Chains together multiple SessionInitiator handlers in sequence.
 */

#include "internal.h"
#include "exceptions.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"
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

    class SHIBSP_DLLLOCAL ChainingSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        ChainingSessionInitiator(const DOMElement* e, const char* appId);
        virtual ~ChainingSessionInitiator() {
            for_each(m_handlers.begin(), m_handlers.end(), xmltooling::cleanup<SessionInitiator>());
        }
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

#ifndef SHIBSP_LITE
        void generateMetadata(opensaml::saml2md::SPSSODescriptor& role, const char* handlerURL) const {
            for (vector<SessionInitiator*>::const_iterator i = m_handlers.begin(); i!=m_handlers.end(); ++i)
                (*i)->generateMetadata(role, handlerURL);
        }
#endif

    private:
        vector<SessionInitiator*> m_handlers;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    static const XMLCh _SessionInitiator[] =    UNICODE_LITERAL_16(S,e,s,s,i,o,n,I,n,i,t,i,a,t,o,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    class SHIBSP_DLLLOCAL SessionInitiatorNodeFilter : public DOMNodeFilter
    {
    public:
        short acceptNode(const DOMNode* node) const {
            if (XMLHelper::isNodeNamed(node,shibspconstants::SHIB2SPCONFIG_NS,_SessionInitiator))
                return FILTER_REJECT;
            return FILTER_ACCEPT;
        }
    };

    static SHIBSP_DLLLOCAL SessionInitiatorNodeFilter g_SINFilter;

    SessionInitiator* SHIBSP_DLLLOCAL ChainingSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new ChainingSessionInitiator(p.first, p.second);
    }
};

ChainingSessionInitiator::ChainingSessionInitiator(const DOMElement* e, const char* appId)
    : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Chaining"), &g_SINFilter)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _SessionInitiator) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_handlers.push_back(conf.SessionInitiatorManager.newPlugin(type.get(),make_pair(e, appId)));
                m_handlers.back()->setParent(this);
            }
            catch (exception& ex) {
                m_log.error("caught exception processing embedded SessionInitiator element: %s", ex.what());
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _SessionInitiator);
    }
}

pair<bool,long> ChainingSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    pair<bool,long> ret;
    for (vector<SessionInitiator*>::const_iterator i = m_handlers.begin(); i!=m_handlers.end(); ++i) {
        ret = (*i)->run(request, entityID, isHandler);
        if (ret.first)
            return ret;
    }
    throw ConfigurationException("None of the configured SessionInitiators handled the request.");
}
