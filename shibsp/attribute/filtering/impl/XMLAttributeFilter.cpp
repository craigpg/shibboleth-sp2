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

    struct SHIBSP_DLLLOCAL Policy
    {
        Policy() : m_applies(NULL) {}
        const MatchFunctor* m_applies;
        typedef multimap<string,const MatchFunctor*> rules_t;
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
        }

        void setDocument(DOMDocument* doc) {
            m_document = doc;
        }

        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const;

    private:
        MatchFunctor* buildFunctor(
            const DOMElement* e, const FilterPolicyContext& functorMap, const char* logname, bool standalone
            );
        pair<string,const MatchFunctor*> buildAttributeRule(const DOMElement* e, const FilterPolicyContext& functorMap, bool standalone);

        Category& m_log;
        DOMDocument* m_document;
        vector<Policy> m_policies;
        map< string,pair<string,const MatchFunctor*> > m_attrRules;
        multimap<string,MatchFunctor*> m_policyReqRules;
        multimap<string,MatchFunctor*> m_permitValRules;
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
    
    if (!XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, AttributeFilterPolicyGroup))
        throw ConfigurationException("XML AttributeFilter requires afp:AttributeFilterPolicyGroup at root of configuration.");

    FilterPolicyContext reqFunctors(m_policyReqRules);
    FilterPolicyContext valFunctors(m_permitValRules);

    DOMElement* child = XMLHelper::getFirstChildElement(e);
    while (child) {
        if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRule)) {
            buildFunctor(child, reqFunctors, "PolicyRequirementRule", true);
        }
        else if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PermitValueRule)) {
            buildFunctor(child, valFunctors, "PermitValueRule", true);
        }
        else if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, AttributeRule)) {
            buildAttributeRule(child, valFunctors, true);
        }
        else if (XMLHelper::isNodeNamed(child, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, AttributeFilterPolicy)) {
            e = XMLHelper::getFirstChildElement(child);
            MatchFunctor* func = NULL;
            if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRule)) {
                func = buildFunctor(e, reqFunctors, "PolicyRequirementRule", false);
            }
            else if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PolicyRequirementRuleReference)) {
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
                    if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, AttributeRule)) {
                        pair<string,const MatchFunctor*> rule = buildAttributeRule(e, valFunctors, false);
                        if (rule.second)
                            m_policies.back().m_rules.insert(Policy::rules_t::value_type(rule.first, rule.second));
                    }
                    else if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, AttributeRuleReference)) {
                        auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
                        if (ref.get() && *ref.get()) {
                            map< string,pair<string,const MatchFunctor*> >::const_iterator ar = m_attrRules.find(ref.get());
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

pair<string,const MatchFunctor*> XMLFilterImpl::buildAttributeRule(const DOMElement* e, const FilterPolicyContext& functorMap, bool standalone)
{
    auto_ptr_char temp(e->getAttributeNS(NULL,_id));
    const char* id = (temp.get() && *temp.get()) ? temp.get() : "";

    if (standalone && !*id) {
        m_log.warn("skipping stand-alone AttributeRule with no id");
        return make_pair(string(),(const MatchFunctor*)NULL);
    }
    else if (*id && m_attrRules.count(id)) {
        if (standalone) {
            m_log.warn("skipping duplicate stand-alone AttributeRule with id (%s)", id);
            return make_pair(string(),(const MatchFunctor*)NULL);
        }
        else
            id = "";
    }

    auto_ptr_char attrID(e->getAttributeNS(NULL,attributeID));
    if (!attrID.get() || !*attrID.get())
        m_log.warn("skipping AttributeRule with no attributeID");

    e = XMLHelper::getFirstChildElement(e);
    MatchFunctor* func=NULL;
    if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PermitValueRule)) {
        func = buildFunctor(e, functorMap, "PermitValueRule", false);
    }
    else if (e && XMLHelper::isNodeNamed(e, shibspconstants::SHIB2ATTRIBUTEFILTER_NS, PermitValueRuleReference)) {
        auto_ptr_char ref(e->getAttributeNS(NULL, _ref));
        if (ref.get() && *ref.get()) {
            multimap<string,MatchFunctor*>::const_iterator pvr = m_permitValRules.find(ref.get());
            func = (pvr!=m_permitValRules.end()) ? pvr->second : NULL;
        }
    }

    if (func) {
        if (*id)
            return m_attrRules[id] = pair<string,const MatchFunctor*>(attrID.get(), func);
        else
            return pair<string,const MatchFunctor*>(attrID.get(), func);
    }

    m_log.warn("skipping AttributeRule (%s), PermitValueRule invalid or missing", id);
    return make_pair(string(),(const MatchFunctor*)NULL);
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

    size_t count,index;

    // Test each Policy.
    for (vector<Policy>::const_iterator p=m_policies.begin(); p!=m_policies.end(); ++p) {
        if (p->m_applies->evaluatePolicyRequirement(context)) {
            // Loop over the attributes and look for possible rules to run.
            for (vector<Attribute*>::size_type a=0; a<attributes.size();) {
                bool ruleFound = false;
                Attribute* attr = attributes[a];
                pair<Policy::rules_t::const_iterator,Policy::rules_t::const_iterator> rules = p->m_rules.equal_range(attr->getId());
                if (rules.first != rules.second) {
                    ruleFound = true;
                    // Run each rule in sequence.
                    m_log.debug(
                        "applying filtering rule(s) for attribute (%s) from (%s)",
                        attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                        );
                    for (; rules.first!=rules.second; ++rules.first) {
                        count = attr->valueCount();
                        for (index=0; index < count;) {
                            // The return value tells us whether to index past the accepted value, or stay put and decrement the count.
                            if (rules.first->second->evaluatePermitValue(context, *attr, index)) {
                                index++;
                            }
                            else {
                                m_log.warn(
                                    "removed value at position (%lu) of attribute (%s) from (%s)",
                                    index, attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                                    );
                                attr->removeValue(index);
                                count--;
                            }
                        }
                    }
                }

                rules = p->m_rules.equal_range("*");
                if (rules.first != rules.second) {
                    // Run each rule in sequence.
                    if (!ruleFound) {
                        m_log.debug(
                            "applying wildcard rule(s) for attribute (%s) from (%s)",
                            attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                            );
                        ruleFound = true;
                    }
                    for (; rules.first!=rules.second; ++rules.first) {
                        count = attr->valueCount();
                        for (index=0; index < count;) {
                            // The return value tells us whether to index past the accepted value, or stay put and decrement the count.
                            if (rules.first->second->evaluatePermitValue(context, *attr, index)) {
                                index++;
                            }
                            else {
                                m_log.warn(
                                    "removed value at position (%lu) of attribute (%s) from (%s)",
                                    index, attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                                    );
                                attr->removeValue(index);
                                count--;
                            }
                        }
                    }
                }

                if (!ruleFound || attr->valueCount() == 0) {
                    if (!ruleFound) {
                        // No rule found, so we're filtering it out.
                        m_log.warn(
                            "no rule found, removing all values of attribute (%s) from (%s)",
                            attr->getId(), issuer.get() ? issuer.get() : "unknown source"
                            );
                    }
                    delete attr;
                    attributes.erase(attributes.begin() + a);
                }
                else {
                    ++a;
                }
            }
        }
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
