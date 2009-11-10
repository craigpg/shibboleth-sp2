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
 * @file shibsp/metadata/MetadataProviderCriteria.h
 *
 * Extended criteria for metadata lookup for Shibboleth-aware metadata providers.
 */

#ifndef __shibsp_metaprovcrit_h__
#define __shibsp_metaprovcrit_h__

#include <shibsp/base.h>

#include <saml/saml2/metadata/MetadataProvider.h>

namespace shibsp {

    class SHIBSP_API Application;

    /**
     * Extended criteria for metadata lookup for Shibboleth-aware metadata providers.
     */
    struct SHIBSP_API MetadataProviderCriteria : public opensaml::saml2md::MetadataProvider::Criteria
    {
        /**
         * Constructor.
         *
         * @param app   application performing the lookup
         */
        MetadataProviderCriteria(const Application& app);

        /**
         * Constructor.
         *
         * @param app   application performing the lookup
         * @param id    entityID to lookup
         * @param q     element/type of role, if any
         * @param prot  protocol support constant, if any
         * @param valid true iff stale metadata should be ignored
         */
        MetadataProviderCriteria(
            const Application& app, const XMLCh* id, const xmltooling::QName* q=NULL, const XMLCh* prot=NULL, bool valid=true
            );

        /**
         * Constructor.
         *
         * @param app   application performing the lookup
         * @param id    entityID to lookup
         * @param q     element/type of role, if any
         * @param prot  protocol support constant, if any
         * @param valid true iff stale metadata should be ignored
         */
        MetadataProviderCriteria(
            const Application& app, const char* id, const xmltooling::QName* q=NULL, const XMLCh* prot=NULL, bool valid=true
            );

        /**
         * Constructor.
         *
         * @param app   application performing the lookup
         * @param a     artifact to lookup
         * @param q     element/type of role, if any
         * @param prot  protocol support constant, if any
         * @param valid true iff stale metadata should be ignored
         */
        MetadataProviderCriteria(
            const Application& app, const opensaml::SAMLArtifact* a, const xmltooling::QName* q=NULL, const XMLCh* prot=NULL, bool valid=true
            );

        ~MetadataProviderCriteria();

        /** The application performing the lookup. */
        const Application& application;
    };
};

#endif /* __shibsp_metaprovcrit_h__ */
