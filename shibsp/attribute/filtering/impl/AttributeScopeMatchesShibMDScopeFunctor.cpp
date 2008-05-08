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
 * AttributeScopeMatchesShibMDScopeFunctor.cpp
 * 
 * A match function that ensures that an attributes value's scope matches a scope given in metadata for the entity or role.
 */

#include "internal.h"
#include "exceptions.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/FilteringContext.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "metadata/MetadataExt.h"

#include <xercesc/util/regx/RegularExpression.hpp>

using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    static const XMLCh groupID[] = UNICODE_LITERAL_7(g,r,o,u,p,I,D);

    /**
     * A match function that ensures that an attributes value's scope matches a scope given in metadata for the entity or role.
     */
    class SHIBSP_DLLLOCAL AttributeScopeMatchesShibMDScopeFunctor : public MatchFunctor
    {
    public:
        bool evaluatePolicyRequirement(const FilteringContext& filterContext) const {
            throw AttributeFilteringException("Metadata scope matching not usable as a PolicyRequirement.");
        }

        bool evaluatePermitValue(const FilteringContext& filterContext, const Attribute& attribute, size_t index) const {
            const RoleDescriptor* issuer = filterContext.getAttributeIssuerMetadata();
            if (!issuer)
                return false;

            const char* scope = attribute.getScope(index);
            if (!scope || !*scope)
                return false;

            const Scope* rule;
            const XMLCh* widescope=NULL;
            const Extensions* ext = issuer->getExtensions();
            if (ext) {
                const vector<XMLObject*>& exts = ext->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator e = exts.begin(); e!=exts.end(); ++e) {
                    rule = dynamic_cast<const Scope*>(*e);
                    if (rule) {
                        if (!widescope)
                            widescope = fromUTF8(scope);
                        if (matches(*rule, widescope)) {
                            delete[] widescope;
                            return true;
                        }
                    }
                }
            }

            ext = dynamic_cast<const EntityDescriptor*>(issuer->getParent())->getExtensions();
            if (ext) {
                const vector<XMLObject*>& exts = ext->getUnknownXMLObjects();
                for (vector<XMLObject*>::const_iterator e = exts.begin(); e!=exts.end(); ++e) {
                    rule = dynamic_cast<const Scope*>(*e);
                    if (rule) {
                        if (!widescope)
                            widescope = fromUTF8(scope);
                        if (matches(*rule, widescope)) {
                            delete[] widescope;
                            return true;
                        }
                    }
                }
            }

            delete[] widescope;
            return false;
        }

    private:
        bool matches(const Scope& rule, const XMLCh* scope) const {
            const XMLCh* val = rule.getValue();
            if (val && *val) {
                if (rule.Regexp()) {
                    RegularExpression re(val);
                    return re.matches(scope);
                }
                else {
                    return XMLString::equals(val, scope);
                }
            }
            return false;
        }
    };

    MatchFunctor* SHIBSP_DLLLOCAL AttributeScopeMatchesShibMDScopeFactory(const std::pair<const FilterPolicyContext*,const DOMElement*>& p)
    {
        return new AttributeScopeMatchesShibMDScopeFunctor();
    }

};
