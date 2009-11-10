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
 * @file shibsp/security/SecurityPolicy.h
 *
 * SP-specific SecurityPolicy subclass.
 */

#ifndef __shibsp_secpol_h__
#define __shibsp_secpol_h__

#include <shibsp/base.h>
#include <saml/saml2/profile/SAML2AssertionPolicy.h>

namespace shibsp {

    class SHIBSP_API Application;

    /**
     * SP-specific SecurityPolicy subclass.
     */
    class SHIBSP_API SecurityPolicy : public opensaml::saml2::SAML2AssertionPolicy
    {
    public:
        /**
         * Constructor for policy.
         *
         * @param application       an Application instance
         * @param role              identifies the role (generally IdP or SP) of the policy peer
         * @param validate          true iff XML parsing should be done with validation
         * @param policyId          identifies policy rules to auto-attach, defaults to the application's set
         */
        SecurityPolicy(const Application& application, const xmltooling::QName* role=NULL, bool validate=true, const char* policyId=NULL);

        virtual ~SecurityPolicy();

        opensaml::saml2md::MetadataProvider::Criteria& getMetadataProviderCriteria() const;

        /**
         * Returns the Application associated with the policy.
         *
         * @return the associated Application
         */
        const Application& getApplication() const;

    private:
        const Application& m_application;
    };

};

#endif /* __shibsp_secpol_h__ */
