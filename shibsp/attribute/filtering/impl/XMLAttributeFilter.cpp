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
 * XMLAttributeFilter.cpp
 *
 * AttributeFilter based on an XML policy language.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/FilterPolicyContext.h"
#include "util/SPConstants.h"

#include <xmltooling/util/NDC.h>
#include <xmltooling/util/ReloadableXMLFile.h>
#include <xmltooling/util/XMLHelper.h>
#include <xercesc/util/XMLUniDefs.hpp>

using shibspconstants::SHIB2ATTRIBUTEFILTER_NS;
using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

    // Each Policy has a functor for determining applicability and a map of
    // attribute IDs to Accept/Deny functor pairs (which can include NULLs).
    struct SHIBSP_DLLLOCAL Policy
    {
        Policy() : m_applies(NULL) {}
        const MatchFunctor* m_applies;
        typedef multimap< string,pair<const MatchFunctor*,const MatchFunctor*> > rules_t;
        rules_t m_rules;
    };

    class SHIBSP_DLLLOCAL XMLFilterImpl
    {
    public:
        XMLFilterImpl(const DOMElement* e, Category& log);
        ~XMLFilterImpl() {
            if (m_document)
                m_document->release();
            for_each(m_policyReqRules.begin(), m_policyReqRules.end(), cleanup_pair<string,MatchFunctor>());
            for_each(m_permitValRules.begin(), m_permitValRules.end(), cleanup_pair<string,MatchFunctor>());
            for_each(m_denyValRules.begin(), m_denyValRules.end(), cleanup_pair<string,MatchFunctor>());
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const;

    private:
        MatchFunctor* buildFunctor(
            const DOMElement* e, const FilterPolicyContext& functorMap, const char* logname, bool standalone
            );
        pair< string,pair<const MatchFunctor*,const MatchFunctor*> > buildAttributeRule(
            const DOMElement* e, const FilterPolicyContext& permMap, const FilterPolicyContext& denyMap, bool standalone
            );

        Category& m_log;
        DOMDocument* m_document;
        vector<Policy> m_policies;
        map< string,pair<string,pair<const MatchFunctor*,const MatchFunctor*> > > m_attrRules;
        multimap<string,MatchFunctor*> m_policyReqRules;
        multimap<string,MatchFunctor*> m_permitValRules;
        multimap<string,MatchFunctor*> m_denyValRules;
    };

    class SHIBSP_DLLLOCAL XMLFilter : public AttributeFilter, public ReloadableXMLFile
    {
    public:
        XMLFilter(const DOMElement* e) : ReloadableXMLFile(e, Category::getInstance(SHIBSP_LOGCAT".AttributeFilter")), m_impl(NULL) {
            load();
        }
        ~XMLFilter() {
            delete m_impl;
        }

        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const {
            m_impl->filterAttributes(context, attributes);
        }

    protected:
        pair<bool,DOMElement*> load();

    private:
        XMLFilterImpl* m_impl;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

    AttributeFilter* SHIBSP_DLLLOCAL XMLAttributeFilterFactory(const DOMElement* const & e)
    {
        return new XMLFilter(e);
    }

    static const XMLCh AttributeFilterPolicyGroup[] =   UNICODE_LITERAL_26(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r,P,o,l,i,c,y,G,r,o,u,p);
    static const XMLCh AttributeFilterPolicy[] =        UNICODE_LITERAL_21(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r,P,o,l,i,c,y);
    static const XMLCh AttributeRule[] =                UNICODE_LITERAL_13(A,t,t,r,i,b,u,t,e,R,u,l,e);
    static const XMLCh AttributeRuleReference[] =       UNICODE_LITERAL_22(A,t,t,r,i,b,u,t,e,R,u,l,e,R,e,f,e,r,e,n,c,e);
    static const XMLCh DenyValueRule[] =                UNICODE_LITERAL_13(D,e,n,y,V,a,l,u,e,R,u,l,e);
    static const XMLCh DenyValueRuleReference[] =       UNICODE_LITERAL_22(D,e,n,y,V,a,l,u,e,R,u,l,e,R,e,f,e,r,e,n,c,e);
    static const XMLCh PermitValueRule[] =              UNICODE_LITERAL_15(P,e,r,m,i,t,V,a,l,u,e,R,u,l,e);
    static const XMLCh PermitValueRuleReference[] =     UNICODE_LITERAL_24(P,e,r,m,i,t,V,a,l,u,e,R,u,l,e,R,e,f,e,r,e,n,c,e);
    static const XMLCh PolicyRequirementRule[] =        UNICODE_LITERAL_21(P,o,l,i,c,y,R,e,q,u,i,r,e,m,e,n,t,R,u,l,e);
    static const XMLCh PolicyRequirementRuleReference[]=UNICODE_LITERAL_30(P,o,l,i,c,y,R,e,q,u,i,r,e,m,e,n,t,R,u,l,e,R,e,f,e,r,e,n,c,e);
    static const XMLCh attributeID[] =                  UNICODE_LITERAL_11(a,t,t,r,i,b,u,t,e,I,D);
    static const XMLCh _id[] =                          UNICODE_LITERAL_2(i,d);
    static const XMLCh _ref[] =                         UNICODE_LITERAL_3(r,e,f);
};

XMLFilterImpl::XMLFilterImpl(const DOMElement* e, Category& log) : m_log(log), m_document(NULL)
{
#ifdef _DEBUG
    xmltooling::NDC ndc("XMLFilterImpl");
#endif

    if (!XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, AttributeFilterPolicyGroup))
        throw ConfigurationException("XML AttributeFilter requires afp:AttributeFilterPolicyGroup at root of configuration.");

    FilterPolicyContext reqFunctors(m_policyReqRules);
    FilterPolicyContext permFunctors(m_permitValRules);
    FilterPolicyContext denyFunctors(m_denyValRules);

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLHelper::isNodeNamed(child, SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRule)) {
            buildFunctor(child, reqFunctors, "PolicyRequirementRule", true);
        }
        else if (XMLHelper::isNodeNamed(child, SHIB2ATTRIBUTEFILTER_NS, PermitValueRule)) {
            buildFunctor(child, permFunctors, "PermitValueRule", true);
        }
        else if (XMLHelper::isNodeNamed(child, SHIB2ATTRIBUTEFILTER_NS, DenyValueRule)) {
            buildFunctor(child, denyFunctors, "DenyValueRule", true);
        }
        else if (XMLHelper::isNodeNamed(child, SHIB2ATTRIBUTEFILTER_NS, AttributeRule)) {
            buildAttributeRule(child, permFunctors, denyFunctors, true);
        }
        else if (XMLHelper::isNodeNamed(child, SHIB2ATTRIBUTEFILTER_NS, AttributeFilterPolicy)) {
            e = XMLHelper::getFirstChildElement(child);
            MatchFunctor* func = NULL;
            if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRule)) {
                func = buildFunctor(e, reqFunctors, "PolicyRequirementRule", false);
            }
            else if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRuleReference)) {
                auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
                if (ref.get() && *ref.get()) {
                    multimap<string,MatchFunctor*>::const_iterator prr = m_policyReqRules.find(ref.get());
                    func = (prr!=m_policyReqRules.end()) ? prr->second : NULL;
                }
            }
            if (func) {
                m_policies.push_back(Policy());
                m_policies.back().m_applies = func;
                e = XMLHelper::getNextSiblingElement(e);
                while (e) {
                    if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, AttributeRule)) {
                        pair< string,pair<const MatchFunctor*,const MatchFunctor*> > rule = buildAttributeRule(e, permFunctors, denyFunctors, false);
                        if (rule.second.first || rule.second.second)
                            m_policies.back().m_rules.insert(Policy::rules_t::value_type(rule.first, rule.second));
                    }
                    else if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, AttributeRuleReference)) {
                        auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
                        if (ref.get() && *ref.get()) {
                            map< string,pair< string,pair< const MatchFunctor*,const MatchFunctor*> > >::const_iterator ar = m_attrRules.find(ref.get());
                            if (ar != m_attrRules.end())
                                m_policies.back().m_rules.insert(Policy::rules_t::value_type(ar->second.first, ar->second.second));
                            else
                                m_log.warn("skipping invalid AttributeRuleReference (%s)", ref.get());
                        }
                    }
                    e = XMLHelper::getNextSiblingElement(e);
                }
            }
            else {
                m_log.warn("skipping AttributeFilterPolicy, PolicyRequirementRule invalid or missing");
            }
        }
        child = XMLHelper::getNextSiblingElement(child);
    }
}

MatchFunctor* XMLFilterImpl::buildFunctor(
    const DOMElement* e, const FilterPolicyContext& functorMap, const char* logname, bool standalone
    )
{
    auto_ptr_char temp(e->getAttributeNS(NULL,_id));
    const char* id = (temp.get() && *temp.get()) ? temp.get() : "";

    if (standalone && !*id) {
        m_log.warn("skipping stand-alone %s with no id", logname);
        return NULL;
    }
    else if (*id && functorMap.getMatchFunctors().count(id)) {
        if (standalone) {
            m_log.warn("skipping duplicate stand-alone %s with id (%s)", logname, id);
            return NULL;
        }
        else
            id = "";
    }

    auto_ptr<QName> type(XMLHelper::getXSIType(e));
    if (type.get()) {
        try {
            MatchFunctor* func = SPConfig::getConfig().MatchFunctorManager.newPlugin(*type.get(), make_pair(&functorMap,e));
            functorMap.getMatchFunctors().insert(multimap<string,MatchFunctor*>::value_type(id, func));
            return func;
        }
        catch (exception& ex) {
            m_log.error("error building %s with type (%s): %s", logname, type->toString().c_str(), ex.what());
        }
    }
    else if (standalone)
        m_log.warn("skipping stand-alone %s with no xsi:type", logname);
    else
        m_log.error("%s with no xsi:type", logname);

    return NULL;
}

pair< string,pair<const MatchFunctor*,const MatchFunctor*> > XMLFilterImpl::buildAttributeRule(
    const DOMElement* e, const FilterPolicyContext& permMap, const FilterPolicyContext& denyMap, bool standalone
    )
{
    auto_ptr_char temp(e->getAttributeNS(NULL,_id));
    const char* id = (temp.get() && *temp.get()) ? temp.get() : "";

    if (standalone && !*id) {
        m_log.warn("skipping stand-alone AttributeRule with no id");
        return make_pair(string(),pair<const MatchFunctor*,const MatchFunctor*>(NULL,NULL));
    }
    else if (*id && m_attrRules.count(id)) {
        if (standalone) {
            m_log.warn("skipping duplicate stand-alone AttributeRule with id (%s)", id);
            return make_pair(string(),pair<const MatchFunctor*,const MatchFunctor*>(NULL,NULL));
        }
        else
            id = "";
    }

    auto_ptr_char attrID(e->getAttributeNS(NULL,attributeID));
    if (!attrID.get() || !*attrID.get())
        m_log.warn("skipping AttributeRule with no attributeID");

    MatchFunctor* perm=NULL;
    MatchFunctor* deny=NULL;

    e = XMLHelper::getFirstChildElement(e);
    if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, PermitValueRule)) {
        perm = buildFunctor(e, permMap, "PermitValueRule", false);
        e = XMLHelper::getNextSiblingElement(e);
    }
    else if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, PermitValueRuleReference)) {
        auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
        if (ref.get() && *ref.get()) {
            multimap<string,MatchFunctor*>::const_iterator pvr = m_permitValRules.find(ref.get());
            perm = (pvr!=m_permitValRules.end()) ? pvr->second : NULL;
        }
        e = XMLHelper::getNextSiblingElement(e);
    }

    if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, DenyValueRule)) {
        deny = buildFunctor(e, denyMap, "DenyValueRule", false);
    }
    else if (e && XMLHelper::isNodeNamed(e, SHIB2ATTRIBUTEFILTER_NS, DenyValueRuleReference)) {
        auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
        if (ref.get() && *ref.get()) {
            multimap<string,MatchFunctor*>::const_iterator pvr = m_denyValRules.find(ref.get());
            deny = (pvr!=m_denyValRules.end()) ? pvr->second : NULL;
        }
    }

    if (perm || deny) {
        if (*id)
            return m_attrRules[id] = pair< string,pair<const MatchFunctor*,const MatchFunctor*> >(attrID.get(), pair<const MatchFunctor*,const MatchFunctor*>(perm,deny));
        else
            return pair< string,pair<const MatchFunctor*,const MatchFunctor*> >(attrID.get(), pair<const MatchFunctor*,const MatchFunctor*>(perm,deny));
    }

    m_log.warn("skipping AttributeRule (%s), permit and denial rule(s) invalid or missing", id);
    return pair< string,pair<const MatchFunctor*,const MatchFunctor*> >(string(),pair<const MatchFunctor*,const MatchFunctor*>(NULL,NULL));
}

void XMLFilterImpl::filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const
{
    auto_ptr_char issuer(context.getAttributeIssuer());

    m_log.debug("filtering %lu attribute(s) from (%s)", attributes.size(), issuer.get() ? issuer.get() : "unknown source");

    if (m_policies.empty()) {
        m_log.warn("no filter policies were loaded, filtering out all attributes from (%s)", issuer.get() ? issuer.get() : "unknown source");
        for_each(attributes.begin(), attributes.end(), xmltooling::cleanup<Attribute>());
        attributes.clear();
        return;
    }

    // We have to evaluate every policy that applies against each attribute before deciding what to keep.

    // For efficiency, we build an array of the policies that apply in advance.
    vector<const Policy*> applicablePolicies;
    for (vector<Policy>::const_iterator p=m_policies.begin(); p!=m_policies.end(); ++p) {
        if (p->m_applies->evaluatePolicyRequirement(context))
            applicablePolicies.push_back(&(*p));
    }

    // For further efficiency, we declare arrays to store the applicable rules for an Attribute.
    vector< pair<const MatchFunctor*,const MatchFunctor*> > applicableRules;
    vector< pair<const MatchFunctor*,const MatchFunctor*> > wildcardRules;

    // Store off the wildcards ahead of time.
    for (vector<const Policy*>::const_iterator pol=applicablePolicies.begin(); pol!=applicablePolicies.end(); ++pol) {
        pair<Policy::rules_t::const_iterator,Policy::rules_t::const_iterator> rules = (*pol)->m_rules.equal_range("*");
        for (; rules.first!=rules.second; ++rules.first)
            wildcardRules.push_back(rules.first->second);
    }

    // To track what to keep without removing anything from the original set until the end, we maintain
    // a map of each Attribute object to a boolean array with true flags indicating what to delete.
    // A single dimension array tracks attributes being removed entirely.
    vector<bool> deletedAttributes(attributes.size(), false);
    map< Attribute*, vector<bool> > deletedPositions;

    // Loop over each attribute to filter them.
    for (vector<Attribute*>::size_type a=0; a<attributes.size(); ++a) {
        Attribute* attr = attributes[a];

        // Clear the rule store.
        applicableRules.clear();

        // Look for rules to run in each policy.
        for (vector<const Policy*>::const_iterator pol=applicablePolicies.begin(); pol!=applicablePolicies.end(); ++pol) {
            pair<Policy::rules_t::const_iterator,Policy::rules_t::const_iterator> rules = (*pol)->m_rules.equal_range(attr->getId());
            for (; rules.first!=rules.second; ++rules.first)
                applicableRules.push_back(rules.first->second);
        }

        // If no rules found, apply wildcards.
        const vector< pair<const MatchFunctor*,const MatchFunctor*> >& rulesToRun = applicableRules.empty() ? wildcardRules : applicableRules;

        // If no rules apply, remove the attribute entirely.
        if (rulesToRun.empty()) {
            m_log.warn(
                "no rule found, removing attribute (%s) from (%s)",
                attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                );
            deletedAttributes[a] = true;
            continue;
        }

        // Run each permit/deny rule.
        m_log.debug(
            "applying filtering rule(s) for attribute (%s) from (%s)",
            attr->getId(), issuer.get() ? issuer.get() : "unknown source"
            );

        bool kickit;

        // Examine each value.
        for (size_t count = attr->valueCount(), index = 0; index < count; ++index) {

            // Assume we're kicking it out.
            kickit=true;

            for (vector< pair<const MatchFunctor*,const MatchFunctor*> >::const_iterator r=rulesToRun.begin(); r!=rulesToRun.end(); ++r) {
                // If there's a permit rule that passes, don't kick it.
                if (r->first && r->first->evaluatePermitValue(context, *attr, index))
                    kickit = false;
                if (!kickit && r->second && r->second->evaluatePermitValue(context, *attr, index))
                    kickit = true;
            }

            // If we're kicking it, record that in the tracker.
            if (kickit) {
                m_log.warn(
                    "removed value at position (%lu) of attribute (%s) from (%s)",
                    index, attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                    );
                deletedPositions[attr].resize(index+1);
                deletedPositions[attr][index] = true;
            }
        }
    }

    // Final step: go over the deletedPositions matrix and apply the actual changes. In order to delete
    // any attributes that end up with no values, we have to do it by looping over the originals.
    for (vector<Attribute*>::size_type a=0; a<attributes.size();) {
        Attribute* attr = attributes[a];

        if (deletedAttributes[a]) {
            delete attr;
            deletedAttributes.erase(deletedAttributes.begin() + a);
            attributes.erase(attributes.begin() + a);
            continue;
        }
        else if (deletedPositions.count(attr) > 0) {
            // To do the removal, we loop over the bits backwards so that the
            // underlying value sequence doesn't get distorted by any removals.
            // Index has to be offset by one because size_type is unsigned.
            const vector<bool>& row = deletedPositions[attr];
            for (vector<bool>::size_type index = row.size(); index > 0; --index) {
                if (row[index-1])
                    attr->removeValue(index-1);
            }

            // Check for no values.
            if (attr->valueCount() == 0) {
                m_log.warn(
                    "no values left, removing attribute (%s) from (%s)",
                    attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                    );
                delete attr;
                attributes.erase(attributes.begin() + a);
                continue;
            }
        }
        ++a;
    }
}

pair<bool,DOMElement*> XMLFilter::load()
{
    // Load from source using base class.
    pair<bool,DOMElement*> raw = ReloadableXMLFile::load();

    // If we own it, wrap it.
    XercesJanitor<DOMDocument> docjanitor(raw.first ? raw.second->getOwnerDocument() : NULL);

    XMLFilterImpl* impl = new XMLFilterImpl(raw.second, m_log);

    // If we held the document, transfer it to the impl. If we didn't, it's a no-op.
    impl->setDocument(docjanitor.release());

    delete m_impl;
    m_impl = impl;

    return make_pair(false,(DOMElement*)NULL);
}
