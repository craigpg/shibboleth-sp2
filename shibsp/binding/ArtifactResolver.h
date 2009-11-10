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
 * @file shibsp/binding/ArtifactResolver.h
 * 
 * SAML artifact resolver for SP use.
 */

#ifndef __shibsp_artres_h__
#define __shibsp_artres_h__

#include <shibsp/base.h>
#include <saml/binding/MessageDecoder.h>

namespace shibsp {

    /**
     * SAML artifact resolver for SP use.
     */
    class SHIBSP_API ArtifactResolver : public opensaml::MessageDecoder::ArtifactResolver {
    public:
        ArtifactResolver();
        virtual ~ArtifactResolver();

        opensaml::saml1p::Response* resolve(
            const std::vector<opensaml::SAMLArtifact*>& artifacts,
            const opensaml::saml2md::IDPSSODescriptor& idpDescriptor,
            opensaml::SecurityPolicy& policy
            ) const;

        opensaml::saml2p::ArtifactResponse* resolve(
            const opensaml::saml2p::SAML2Artifact& artifact,
            const opensaml::saml2md::SSODescriptorType& ssoDescriptor,
            opensaml::SecurityPolicy& policy
            ) const;
    };
};

#endif /* __shibsp_artres_h__ */
