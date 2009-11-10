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
 * MetadataProviderCriteria.cpp
 *
 * Extended criteria for metadata lookup for Shibboleth-aware metadata providers.
 */

#include "internal.h"
#include "metadata/MetadataProviderCriteria.h"

using namespace shibsp;
using namespace opensaml::saml2md;
using opensaml::SAMLArtifact;
using namespace xmltooling;

MetadataProviderCriteria::MetadataProviderCriteria(const Application& app) : application(app)
{
}

MetadataProviderCriteria::MetadataProviderCriteria(
    const Application& app, const XMLCh* id, const xmltooling::QName* q, const XMLCh* prot, bool valid
    ) : MetadataProvider::Criteria(id, q, prot, valid), application(app)
{
}

MetadataProviderCriteria::MetadataProviderCriteria(
    const Application& app, const char* id, const xmltooling::QName* q, const XMLCh* prot, bool valid
    ) : MetadataProvider::Criteria(id, q, prot, valid), application(app)
{
}

MetadataProviderCriteria::MetadataProviderCriteria(
    const Application& app, const SAMLArtifact* a, const xmltooling::QName* q, const XMLCh* prot, bool valid
    ) : MetadataProvider::Criteria(a, q, prot, valid), application(app)
{
}

MetadataProviderCriteria::~MetadataProviderCriteria()
{
}
