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
 * SessionInitiator.cpp
 * 
 * Pluggable runtime functionality that handles initiating sessions.
 */

#include "internal.h"
#include "SPRequest.h"
#include "handler/SessionInitiator.h"

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory ChainingSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory Shib1SessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory SAML2SessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory WAYFSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory SAMLDSSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory TransformSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory FormSessionInitiatorFactory;
    SHIBSP_DLLLOCAL PluginManager< SessionInitiator,string,pair<const DOMElement*,const char*> >::Factory CookieSessionInitiatorFactory;
};

map<string,string> SessionInitiator::m_remapper;

void SHIBSP_API shibsp::registerSessionInitiators()
{
    SPConfig& conf=SPConfig::getConfig();
    conf.SessionInitiatorManager.registerFactory(CHAINING_SESSION_INITIATOR, ChainingSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SHIB1_SESSION_INITIATOR, Shib1SessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SAML2_SESSION_INITIATOR, SAML2SessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(WAYF_SESSION_INITIATOR, WAYFSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(SAMLDS_SESSION_INITIATOR, SAMLDSSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(TRANSFORM_SESSION_INITIATOR, TransformSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(FORM_SESSION_INITIATOR, FormSessionInitiatorFactory);
    conf.SessionInitiatorManager.registerFactory(COOKIE_SESSION_INITIATOR, CookieSessionInitiatorFactory);

    SessionInitiator::m_remapper["defaultACSIndex"] = "acsIndex";
}

SessionInitiator::SessionInitiator()
{
}

SessionInitiator::~SessionInitiator()
{
}

#ifndef SHIBSP_LITE
const char* SessionInitiator::getType() const
{
    return "SessionInitiator";
}
#endif

pair<bool,long> SessionInitiator::run(SPRequest& request, bool isHandler) const
{
    const char* entityID=NULL;
    pair<bool,const char*> param = getString("entityIDParam");

    if (isHandler) {
        entityID=request.getParameter(param.first ? param.second : "entityID");
        if (!param.first && (!entityID || !*entityID))
            entityID=request.getParameter("providerId");
    }
    if (!entityID || !*entityID) {
        RequestMapper::Settings settings = request.getRequestSettings();
        param = settings.first->getString("entityID");
        if (param.first)
            entityID = param.second;
    }
    if (!entityID || !*entityID)
        entityID=getString("entityID").second;

    string copy(entityID ? entityID : "");
    return run(request, copy, isHandler);
}
