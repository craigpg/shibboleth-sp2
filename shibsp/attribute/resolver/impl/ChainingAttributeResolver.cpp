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
 * ChainingAttributeResolver.cpp
 *
 * Chains together multiple AttributeResolver plugins.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeResolver.h"
#include "attribute/resolver/ResolutionContext.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    struct SHIBSP_DLLLOCAL ChainingContext : public ResolutionContext
    {
        ChainingContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid,
            const XMLCh* authncontext_class,
            const XMLCh* authncontext_decl,
            const vector<const opensaml::Assertion*>* tokens,
            const vector<shibsp::Attribute*>* attributes
            ) : m_app(application), m_issuer(issuer), m_protocol(protocol), m_nameid(nameid), m_authclass(authncontext_class), m_authdecl(authncontext_decl), m_session(NULL) {
            if (tokens)
                m_tokens.assign(tokens->begin(), tokens->end());
            if (attributes)
                m_attributes.assign(attributes->begin(), attributes->end());
        }

        ChainingContext(const Application& application, const Session& session) : m_app(application), m_session(&session) {
        }

        ~ChainingContext() {
            for_each(m_ownedAttributes.begin(), m_ownedAttributes.end(), xmltooling::cleanup<shibsp::Attribute>());
            for_each(m_ownedAssertions.begin(), m_ownedAssertions.end(), xmltooling::cleanup<opensaml::Assertion>());
        }

        vector<shibsp::Attribute*>& getResolvedAttributes() {
            return m_ownedAttributes;
        }
        vector<opensaml::Assertion*>& getResolvedAssertions() {
            return m_ownedAssertions;
        }

        vector<shibsp::Attribute*> m_ownedAttributes;
        vector<opensaml::Assertion*> m_ownedAssertions;

        const Application& m_app;
        const EntityDescriptor* m_issuer;
        const XMLCh* m_protocol;
        const NameID* m_nameid;
        const XMLCh* m_authclass;
        const XMLCh* m_authdecl;
        vector<const opensaml::Assertion*> m_tokens;
        vector<shibsp::Attribute*> m_attributes;

        const Session* m_session;
    };

    class SHIBSP_DLLLOCAL ChainingAttributeResolver : public AttributeResolver
    {
    public:
        ChainingAttributeResolver(const DOMElement* e);
        virtual ~ChainingAttributeResolver() {
            for_each(m_resolvers.begin(), m_resolvers.end(), xmltooling::cleanup<AttributeResolver>());
        }

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

        ResolutionContext* createResolutionContext(
            const Application& application,
            const EntityDescriptor* issuer,
            const XMLCh* protocol,
            const NameID* nameid=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL,
            const vector<const opensaml::Assertion*>* tokens=NULL,
            const vector<shibsp::Attribute*>* attributes=NULL
            ) const {
            return new ChainingContext(application, issuer, protocol, nameid, authncontext_class, authncontext_decl, tokens, attributes);
        }

        ResolutionContext* createResolutionContext(const Application& application, const Session& session) const {
            return new ChainingContext(application, session);
        }

        void resolveAttributes(ResolutionContext& ctx) const;

        void getAttributeIds(vector<string>& attributes) const {
            for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i) {
                Locker locker(*i);
                (*i)->getAttributeIds(attributes);
            }
        }

    private:
        vector<AttributeResolver*> m_resolvers;
    };

    static const XMLCh _AttributeResolver[] =   UNICODE_LITERAL_17(A,t,t,r,i,b,u,t,e,R,e,s,o,l,v,e,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    SHIBSP_DLLLOCAL PluginManager<AttributeResolver,string,const DOMElement*>::Factory QueryResolverFactory;
    AttributeResolver* SHIBSP_DLLLOCAL ChainingResolverFactory(const DOMElement* const & e)
    {
        return new ChainingAttributeResolver(e);
    }
};

void SHIBSP_API shibsp::registerAttributeResolvers()
{
    SPConfig::getConfig().AttributeResolverManager.registerFactory(QUERY_ATTRIBUTE_RESOLVER, QueryResolverFactory);
    SPConfig::getConfig().AttributeResolverManager.registerFactory(CHAINING_ATTRIBUTE_RESOLVER, ChainingResolverFactory);
}

ChainingAttributeResolver::ChainingAttributeResolver(const DOMElement* e)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _AttributeResolver) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_resolvers.push_back(conf.AttributeResolverManager.newPlugin(type.get(),e));
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeResolver.Chaining").error(
                    "caught exception processing embedded AttributeResolver element: %s", ex.what()
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeResolver);
    }
}

void ChainingAttributeResolver::resolveAttributes(ResolutionContext& ctx) const
{
    ChainingContext& chain = dynamic_cast<ChainingContext&>(ctx);
    for (vector<AttributeResolver*>::const_iterator i=m_resolvers.begin(); i!=m_resolvers.end(); ++i) {
        Locker locker(*i);
        auto_ptr<ResolutionContext> context(
            chain.m_session ?
                (*i)->createResolutionContext(chain.m_app, *chain.m_session) :
                (*i)->createResolutionContext(
                    chain.m_app, chain.m_issuer, chain.m_protocol, chain.m_nameid, chain.m_authclass, chain.m_authdecl, &chain.m_tokens, &chain.m_attributes
                    )
            );

        (*i)->resolveAttributes(*context.get());

        chain.m_attributes.insert(chain.m_attributes.end(), context->getResolvedAttributes().begin(), context->getResolvedAttributes().end());
        chain.m_ownedAttributes.insert(chain.m_attributes.end(), context->getResolvedAttributes().begin(), context->getResolvedAttributes().end());
        context->getResolvedAttributes().clear();

        chain.m_tokens.insert(chain.m_tokens.end(), context->getResolvedAssertions().begin(), context->getResolvedAssertions().end());
        chain.m_ownedAssertions.insert(chain.m_ownedAssertions.end(), context->getResolvedAssertions().begin(), context->getResolvedAssertions().end());
        context->getResolvedAssertions().clear();
    }
}
