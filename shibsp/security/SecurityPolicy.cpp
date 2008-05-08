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
 * SecurityPolicy.cpp
 * 
 * SP-specific SecurityPolicy subclass.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "security/SecurityPolicy.h"

using namespace shibsp;

SecurityPolicy::SecurityPolicy(const Application& application, const xmltooling::QName* role, bool validate)
    : opensaml::SecurityPolicy(application.getMetadataProvider(), role, application.getTrustEngine(), validate), m_application(application) {

    const std::vector<const opensaml::SecurityPolicyRule*>& rules =
        application.getServiceProvider().getPolicyRules(application.getString("policyId").second);
    getRules().assign(rules.begin(), rules.end());
}
