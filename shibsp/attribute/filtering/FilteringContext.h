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
 * @file shibsp/attribute/filtering/FilteringContext.h
 * 
 * Context for attribute filtering operations.
 */

#ifndef __shibsp_filtctx_h__
#define __shibsp_filtctx_h__

#include <shibsp/base.h>

#include <map>
#include <string>

namespace opensaml {
    namespace saml2md {
        class SAML_API RoleDescriptor;
    };
};

namespace shibsp {

    class SHIBSP_API Application;
    class SHIBSP_API Attribute;

    /**
     * Context for attribute filtering operations.
     */
    class SHIBSP_API FilteringContext
    {
        MAKE_NONCOPYABLE(FilteringContext);
    protected:
        FilteringContext();
    public:
        virtual ~FilteringContext();

        /**
         * Gets the Application doing the filtering.
         *
         * @return  reference to an Application
         */
        virtual const Application& getApplication() const=0;

        /**
         * Returns a URI containing an AuthnContextClassRef associated with the subject.
         * 
         * <p>SAML 1.x AuthenticationMethods will be returned as class references.
         * 
         * @return  a URI identifying the authentication context class
         */
        virtual const XMLCh* getAuthnContextClassRef() const=0;

        /**
         * Returns a URI containing an AuthnContextDeclRef associated with the subject.
         * 
         * @return  a URI identifying the authentication context declaration
         */
        virtual const XMLCh* getAuthnContextDeclRef() const=0;

        /**
         * Gets the ID of the requester of the attributes, if known.
         * 
         * @return requester of the attributes, or NULL
         */
        virtual const XMLCh* getAttributeRequester() const=0;
        
        /**
         * Gets the ID of the issuer of the attributes, if known.
         * 
         * @return ID of the issuer of the attributes, or NULL
         */
        virtual const XMLCh* getAttributeIssuer() const=0;

        /**
         * Gets the SAML metadata for the attribute requesting role, if available.
         * 
         * @return SAML metadata for the attribute requesting role, or NULL
         */
        virtual const opensaml::saml2md::RoleDescriptor* getAttributeRequesterMetadata() const=0;
        
        /**
         * Gets the SAML metadata for the attribute issuing role, if available.
         * 
         * @return SAML metadata for the attribute issuing role, or NULL
         */
        virtual const opensaml::saml2md::RoleDescriptor* getAttributeIssuerMetadata() const=0;

        /**
         * Returns the set of Attributes being filtered.
         * 
         * <p>No modifications should be performed, access is provided only for use by
         * MatchFunctors based on the presence of Attribute data.
         * 
         * @return  an immutable map of Attributes.
         */
        virtual const std::multimap<std::string,Attribute*>& getAttributes() const=0;

    };
};

#endif /* __shibsp_filtctx_h__ */
