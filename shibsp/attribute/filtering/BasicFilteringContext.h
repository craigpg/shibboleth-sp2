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
 * @file shibsp/attribute/filtering/BasicFilteringContext.h
 * 
 * A trivial FilteringContext implementation.
 */

#ifndef __shibsp_basicfiltctx_h__
#define __shibsp_basicfiltctx_h__

#include <shibsp/attribute/filtering/FilteringContext.h>

namespace shibsp {

    class SHIBSP_API Attribute;

    class SHIBSP_API BasicFilteringContext : public FilteringContext
    {
    public:
        /**
         * Constructor.
         *
         * @param app                   reference to Application
         * @param attributes            attributes being filtered
         * @param role                  metadata role of Attribute issuer, if any
         * @param authncontext_class    method/category of authentication event, if known
         * @param authncontext_decl     specifics of authentication event, if known
         */
        BasicFilteringContext(
            const Application& app,
            const std::vector<Attribute*>& attributes,
            const opensaml::saml2md::RoleDescriptor* role=NULL,
            const XMLCh* authncontext_class=NULL,
            const XMLCh* authncontext_decl=NULL
            );

        virtual ~BasicFilteringContext();

        // Virtual function overrides.
        const Application& getApplication() const;
        const XMLCh* getAuthnContextClassRef() const;
        const XMLCh* getAuthnContextDeclRef() const;
        const XMLCh* getAttributeRequester() const;
        const XMLCh* getAttributeIssuer() const;
        const opensaml::saml2md::RoleDescriptor* getAttributeRequesterMetadata() const;
        const opensaml::saml2md::RoleDescriptor* getAttributeIssuerMetadata() const;
        const std::multimap<std::string,Attribute*>& getAttributes() const;

    private:
        const Application& m_app;
        std::multimap<std::string,Attribute*> m_attributes;
        const opensaml::saml2md::RoleDescriptor* m_role;
        const XMLCh* m_issuer;
        const XMLCh* m_class;
        const XMLCh* m_decl;
    };
};

#endif /* __shibsp_basicfiltctx_h__ */
