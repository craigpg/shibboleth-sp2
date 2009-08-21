/*
 *  Copyright 2001-2009 Internet2
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
 * WAYFSessionInitiator.cpp
 * 
 * Shibboleth WAYF support.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"

#include <ctime>
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

    class SHIBSP_DLLLOCAL WAYFSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        WAYFSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.WAYF")), m_url(NULL) {
            pair<bool,const char*> url = getString("URL");
            if (!url.first)
                throw ConfigurationException("WAYF SessionInitiator requires a URL property.");
            m_url = url.second;
        }
        virtual ~WAYFSessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        const char* m_url;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL WAYFSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new WAYFSessionInitiator(p.first, p.second);
    }

};

pair<bool,long> WAYFSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // The IdP CANNOT be specified for us to run. Otherwise, we'd be redirecting to a WAYF
    // anytime the IdP's metadata was wrong.
    if (!entityID.empty())
        return make_pair(false,0L);

    string target;
    string postData;
    const char* option;
    const Handler* ACS=NULL;
    const Application& app=request.getApplication();

    if (isHandler) {
        option=request.getParameter("acsIndex");
        if (option) {
            ACS=app.getAssertionConsumerServiceByIndex(atoi(option));
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid acsIndex specified in request, using default ACS location");
        }

        option = request.getParameter("target");
        if (option)
            target = option;
        recoverRelayState(request.getApplication(), request, request, target, false);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one and everything else is defaulted.
        target=request.getRequestURL();
    }
    
    // Since we're not passing by index, we need to fully compute the return URL.
    if (!ACS) {
        pair<bool,unsigned int> index = getUnsignedInt("defaultACSIndex");
        if (index.first) {
            ACS = app.getAssertionConsumerServiceByIndex(index.second);
            if (!ACS)
                request.log(SPRequest::SPWarn, "invalid defaultACSIndex, using default ACS location");
        }
        if (!ACS)
            ACS = app.getDefaultAssertionConsumerService();
    }

    // Validate the ACS for use with this protocol.
    pair<bool,const char*> ACSbinding = ACS ? ACS->getString("Binding") : pair<bool,const char*>(false,NULL);
    if (ACSbinding.first) {
        pair<bool,const char*> compatibleBindings = getString("compatibleBindings");
        if (compatibleBindings.first && strstr(compatibleBindings.second, ACSbinding.second) == NULL) {
            m_log.info("configured or requested ACS has non-SAML 1.x binding");
            return make_pair(false,0L);
        }
        else if (strcmp(ACSbinding.second, samlconstants::SAML1_PROFILE_BROWSER_POST) &&
                 strcmp(ACSbinding.second, samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT)) {
            m_log.info("configured or requested ACS has non-SAML 1.x binding");
            return make_pair(false,0L);
        }
    }

    m_log.debug("sending request to WAYF (%s)", m_url);

    // Compute the ACS URL. We add the ACS location to the base handlerURL.
    string ACSloc=request.getHandlerURL(target.c_str());
    pair<bool,const char*> loc=ACS ? ACS->getString("Location") : pair<bool,const char*>(false,NULL);
    if (loc.first) ACSloc+=loc.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        option = request.getParameter("target");
        if (option)
            target = option;
    }
    preserveRelayState(request.getApplication(), request, target);
    if (!isHandler)
        preservePostData(request.getApplication(), request, request, target.c_str());

    // WAYF requires a target value.
    if (target.empty())
        target = "default";

    char timebuf[16];
    sprintf(timebuf,"%lu",time(NULL));
    const URLEncoder* urlenc = XMLToolingConfig::getConfig().getURLEncoder();
    string req=string(m_url) + (strchr(m_url,'?') ? '&' : '?') + "shire=" + urlenc->encode(ACSloc.c_str()) +
        "&time=" + timebuf + "&target=" + urlenc->encode(target.c_str()) +
        "&providerId=" + urlenc->encode(app.getString("entityID").second);

    return make_pair(true, request.sendRedirect(req.c_str()));
}
