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
 * TransformSessionInitiator.cpp
 * 
 * Support for mapping input into an entityID using a transform.
 */

#include "internal.h"
#include "Application.h"
#include "exceptions.h"
#include "ServiceProvider.h"
#include "SPRequest.h"
#include "handler/AbstractHandler.h"
#include "handler/RemotedHandler.h"
#include "handler/SessionInitiator.h"
#include "util/SPConstants.h"

#ifndef SHIBSP_LITE
# include "metadata/MetadataProviderCriteria.h"
# include <saml/saml2/metadata/Metadata.h>
#endif
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/URLEncoder.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xercesc/util/regx/RegularExpression.hpp>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    class SHIBSP_DLLLOCAL TransformSINodeFilter : public DOMNodeFilter
    {
    public:
#ifdef SHIBSP_XERCESC_SHORT_ACCEPTNODE
        short
#else
        FilterAction
#endif
        acceptNode(const DOMNode* node) const {
            return FILTER_REJECT;
        }
    };

    static SHIBSP_DLLLOCAL TransformSINodeFilter g_TSINFilter;

#ifndef SHIBSP_LITE
    static const XMLCh force[] =        UNICODE_LITERAL_5(f,o,r,c,e);
    static const XMLCh match[] =        UNICODE_LITERAL_5(m,a,t,c,h);
    static const XMLCh Regex[] =        UNICODE_LITERAL_5(R,e,g,e,x);
    static const XMLCh Subst[] =        UNICODE_LITERAL_5(S,u,b,s,t);
#endif

    class SHIBSP_DLLLOCAL TransformSessionInitiator : public SessionInitiator, public AbstractHandler, public RemotedHandler
    {
    public:
        TransformSessionInitiator(const DOMElement* e, const char* appId)
                : AbstractHandler(e, Category::getInstance(SHIBSP_LOGCAT".SessionInitiator.Transform"), &g_TSINFilter), m_appId(appId) {
            // If Location isn't set, defer address registration until the setParent call.
            pair<bool,const char*> loc = getString("Location");
            if (loc.first) {
                string address = m_appId + loc.second + "::run::TransformSI";
                setAddress(address.c_str());
            }

#ifndef SHIBSP_LITE
            if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess)) {
                m_alwaysRun = getBool("alwaysRun").second;
                e = XMLHelper::getFirstChildElement(e);
                while (e) {
                    if (e->hasChildNodes()) {
                        const XMLCh* flag = e->getAttributeNS(NULL, force);
                        if (!flag)
                            flag = &chNull;
                        if (XMLString::equals(e->getLocalName(), Subst)) {
                            auto_ptr_char temp(e->getFirstChild()->getNodeValue());
                            m_subst.push_back(pair<bool,string>((*flag==chDigit_1 || *flag==chLatin_t), temp.get()));
                        }
                        else if (XMLString::equals(e->getLocalName(), Regex) && e->hasAttributeNS(NULL, match)) {
                            auto_ptr_char m(e->getAttributeNS(NULL, match));
                            auto_ptr_char repl(e->getFirstChild()->getNodeValue());
                            m_regex.push_back(make_pair((*flag==chDigit_1 || *flag==chLatin_t), pair<string,string>(m.get(), repl.get())));
                        }
                        else {
                            m_log.warn("Unknown element found in Transform SessionInitiator configuration, check for errors.");
                        }
                    }
                    e = XMLHelper::getNextSiblingElement(e);
                }
            }
#endif
        }

        virtual ~TransformSessionInitiator() {}
        
        void setParent(const PropertySet* parent);
        void receive(DDF& in, ostream& out);
        pair<bool,long> run(SPRequest& request, string& entityID, bool isHandler=true) const;

    private:
        void doRequest(const Application& application, string& entityID) const;
        string m_appId;
#ifndef SHIBSP_LITE
        bool m_alwaysRun;
        vector< pair<bool, string> > m_subst;
        vector< pair< bool, pair<string,string> > > m_regex;
#endif
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    SessionInitiator* SHIBSP_DLLLOCAL TransformSessionInitiatorFactory(const pair<const DOMElement*,const char*>& p)
    {
        return new TransformSessionInitiator(p.first, p.second);
    }

};

void TransformSessionInitiator::setParent(const PropertySet* parent)
{
    DOMPropertySet::setParent(parent);
    pair<bool,const char*> loc = getString("Location");
    if (loc.first) {
        string address = m_appId + loc.second + "::run::TransformSI";
        setAddress(address.c_str());
    }
    else {
        m_log.warn("no Location property in Transform SessionInitiator (or parent), can't register as remoted handler");
    }
}

pair<bool,long> TransformSessionInitiator::run(SPRequest& request, string& entityID, bool isHandler) const
{
    // We have to have a candidate name to function.
    if (entityID.empty())
        return make_pair(false,0L);

    string target;
    const Application& app=request.getApplication();

    m_log.debug("attempting to transform input (%s) into a valid entityID", entityID.c_str());

    if (SPConfig::getConfig().isEnabled(SPConfig::OutOfProcess))
        doRequest(app, entityID);
    else {
        // Remote the call.
        DDF out,in = DDF(m_address.c_str()).structure();
        DDFJanitor jin(in), jout(out);
        in.addmember("application_id").string(app.getId());
        in.addmember("entity_id").string(entityID.c_str());
    
        // Remote the processing.
        out = request.getServiceProvider().getListenerService()->send(in);
        if (out.isstring())
            entityID = out.string();
    }
    
    return make_pair(false,0L);
}

void TransformSessionInitiator::receive(DDF& in, ostream& out)
{
    // Find application.
    const char* aid=in["application_id"].string();
    const Application* app=aid ? SPConfig::getConfig().getServiceProvider()->getApplication(aid) : NULL;
    if (!app) {
        // Something's horribly wrong.
        m_log.error("couldn't find application (%s) to generate AuthnRequest", aid ? aid : "(missing)");
        throw ConfigurationException("Unable to locate application for new session, deleted?");
    }

    const char* entityID = in["entity_id"].string();
    if (!entityID)
        throw ConfigurationException("No entityID parameter supplied to remoted SessionInitiator.");

    string copy(entityID);
    doRequest(*app, copy);
    DDF ret = DDF(NULL).string(copy.c_str());
    DDFJanitor jout(ret);
    out << ret;
}

void TransformSessionInitiator::doRequest(const Application& application, string& entityID) const
{
#ifndef SHIBSP_LITE
    MetadataProvider* m=application.getMetadataProvider();
    Locker locker(m);

    MetadataProviderCriteria mc(application, entityID.c_str(), &IDPSSODescriptor::ELEMENT_QNAME);
    pair<const EntityDescriptor*,const RoleDescriptor*> entity;
    if (!m_alwaysRun) {
        // First check the original value, it might be valid already.
        entity = m->getEntityDescriptor(mc);
        if (entity.first)
            return;
    }

    m_log.debug("attempting transform of (%s)", entityID.c_str());

    // Guess not, try each subst.
    string transform;
    for (vector< pair<bool,string> >::const_iterator t = m_subst.begin(); t != m_subst.end(); ++t) {
        string::size_type pos = t->second.find("$entityID");
        if (pos == string::npos)
            continue;
        transform = t->second;
        transform.replace(pos, 9, entityID);
        if (t->first) {
            m_log.info("forcibly transformed entityID from (%s) to (%s)", entityID.c_str(), transform.c_str());
            entityID = transform;
        }

        m_log.debug("attempting lookup with entityID (%s)", transform.c_str());
    
        mc.entityID_ascii = transform.c_str();
        entity = m->getEntityDescriptor(mc);
        if (entity.first) {
            m_log.info("transformed entityID from (%s) to (%s)", entityID.c_str(), transform.c_str());
            if (!t->first)
                entityID = transform;
            return;
        }
    }

    // Now try regexs.
    for (vector< pair< bool, pair<string,string> > >::const_iterator r = m_regex.begin(); r != m_regex.end(); ++r) {
        try {
            RegularExpression exp(r->second.first.c_str());
            XMLCh* temp = exp.replace(entityID.c_str(), r->second.second.c_str());
            if (temp) {
                auto_ptr_char narrow(temp);
                XMLString::release(&temp);

                // For some reason it returns the match string if it doesn't match the expression.
                if (entityID == narrow.get())
                    continue;

                if (r->first) {
                    m_log.info("forcibly transformed entityID from (%s) to (%s)", entityID.c_str(), narrow.get());
                    entityID = narrow.get();
                }

                m_log.debug("attempting lookup with entityID (%s)", narrow.get());

                mc.entityID_ascii = narrow.get();
                entity = m->getEntityDescriptor(mc);
                if (entity.first) {
                    m_log.info("transformed entityID from (%s) to (%s)", entityID.c_str(), narrow.get());
                    if (!r->first)
                        entityID = narrow.get();
                    return;
                }
            }
        }
        catch (XMLException& ex) {
            auto_ptr_char msg(ex.getMessage());
            m_log.error("caught error applying regular expression: %s", msg.get());
        }
    }

    m_log.warn("unable to find a valid entityID based on the supplied input");
#endif
}
