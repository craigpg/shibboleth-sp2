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
 * CookieSessionInitiator.cpp
 * 
 * Cookie-based IdP discovery.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"

#ifndef SHIBSP_LITE
# include <saml/util/CommonDomainCookie.h>
#else
# include "lite/CommonDomainCookie.h"
#endif

#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>

using namespace shibsp;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL CookieSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        CookieSessionInitiator(const DOMElement* e, const char* appId)
            : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Cookie")), m_followMultiple(getBool("followMultiple").second) {
        }
        virtual ~CookieSessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        bool m_followMultiple;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL CookieSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new CookieSessionInitiator(p.first, p.second);
    }

};

pair<bool,long> CookieSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // The IdP CANNOT be specified for us to run.
    if (!entityID.empty())
        return make_pair(false,0L);

    // If there's no entityID yet, we can check for cookie processing.
    CommonDomainCookie cdc(request.getCookie(CommonDomainCookie::CDCName));
    if ((m_followMultiple && cdc.get().size() > 0) || (!m_followMultiple && cdc.get().size() == 1)) {
        entityID = cdc.get().back();
        m_log.info("set entityID (%s) from IdP history cookie", entityID.c_str());
    }
    
    return make_pair(false,0L);
}
