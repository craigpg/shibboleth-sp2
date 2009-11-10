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
 * SecurityPolicy.cpp
 *
 * SP-specific SecurityPolicy subclass.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "metadata/MetadataProviderCriteria.h"
#include "security/SecurityPolicy.h"

using namespace shibsp;
using namespace opensaml::saml2;
using namespace std;

SecurityPolicy::SecurityPolicy(const Application& application, const xmltooling::QName* role, bool validate, const char* policyId)
        : opensaml::SecurityPolicy(application.getMetadataProvider(), role, application.getTrustEngine(), validate), m_application(application) {
    const vector<const opensaml::SecurityPolicyRule*>& rules =
        application.getServiceProvider().getPolicyRules(policyId ? policyId : application.getString("policyId").second);
    getRules().assign(rules.begin(), rules.end());

    // Populate audiences.
    if (application.getAudiences()) {
        for (vector<const XMLCh*>::const_iterator a = application.getAudiences()->begin(); a != application.getAudiences()->end(); ++a)
            getAudiences().push_back(*a);
    }
}

SecurityPolicy::~SecurityPolicy()
{
}

opensaml::saml2md::MetadataProvider::Criteria& SecurityPolicy::getMetadataProviderCriteria() const
{
    if (!m_metadataCriteria)
        m_metadataCriteria=new MetadataProviderCriteria(m_application);
    else
        m_metadataCriteria->reset();
    return *m_metadataCriteria;
}

const Application& SecurityPolicy::getApplication() const
{
    return m_application;
}
