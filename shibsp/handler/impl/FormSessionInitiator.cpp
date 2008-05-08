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
 * FormSessionInitiator.cpp
 * 
 * HTML form-based IdP discovery.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/SessionInitiator.h"
#include "util/TemplateParameters.h"

#include <fstream>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/PathResolver.h>
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

    class SHIBSP_DLLLOCAL FormSessionInitiator : public SessionInitiator, public AbstractHandler
    {
    public:
        FormSessionInitiator(const DOMElement* e, const char* appId)
            : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Form")), m_template(getString("template").second) {
            if (!m_template)
                throw ConfigurationException("Form SessionInitiator requires a template property.");
        }
        virtual ~FormSessionInitiator() {}
        
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        const char* m_template;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL FormSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new FormSessionInitiator(p.first, p.second);
    }

};

pair<bool,long> FormSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    string target;
    const char* option;
    const Application& app=request.getApplication();

    if (isHandler) {
        option = request.getParameter("target");
        if (option)
            target = option;
        recoverRelayState(app, request, request, target, false);
    }
    else {
        // We're running as a "virtual handler" from within the filter.
        // The target resource is the current one.
        target=request.getRequestURL();
    }

    // Compute the return URL. We start with a self-referential link.
    string returnURL=request.getHandlerURL(target.c_str());
    pair<bool,const char*> thisloc = getString("Location");
    if (thisloc.first) returnURL += thisloc.second;

    if (isHandler) {
        // We may already have RelayState set if we looped back here,
        // but just in case target is a resource, we reset it back.
        option = request.getParameter("target");
        if (option)
            target = option;
    }
    preserveRelayState(app, request, target);

    request.setContentType("text/html");
    request.setResponseHeader("Expires","01-Jan-1997 12:00:00 GMT");
    request.setResponseHeader("Cache-Control","private,no-store,no-cache");
    string fname(m_template);
    ifstream infile(XMLToolingConfig::getConfig().getPathResolver()->resolve(fname, PathResolver::XMLTOOLING_CFG_FILE).c_str());
    if (!infile)
        throw ConfigurationException("Unable to access HTML template ($1).", params(1, m_template));
    TemplateParameters tp;
    tp.m_request = &request;
    tp.setPropertySet(app.getPropertySet("Errors"));
    tp.m_map["action"] = returnURL;
    if (!target.empty())
        tp.m_map["target"] = target;
    stringstream str;
    XMLToolingConfig::getConfig().getTemplateEngine()->run(infile, str, tp);
    return make_pair(true,request.sendResponse(str));
}
