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
 * ChainingAttributeExtractor.cpp
 *
 * Chains together multiple AttributeExtractor plugins.
 */

#include "internal.h"
#include "Application.h"
#include "ServiceProvider.h"
#include "attribute/Attribute.h"
#include "attribute/resolver/AttributeExtractor.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL ChainingAttributeExtractor : public AttributeExtractor
    {
    public:
        ChainingAttributeExtractor(const DOMElement* e);
        virtual ~ChainingAttributeExtractor() {
            for_each(m_extractors.begin(), m_extractors.end(), xmltooling::cleanup<AttributeExtractor>());
        }

        Lockable* lock() {
            return this;
        }
        void unlock() {
        }

        void extractAttributes(
            const Application& application,
            const RoleDescriptor* issuer,
            const XMLObject& xmlObject,
            vector<Attribute*>& attributes
            ) const;

        void getAttributeIds(vector<string>& attributes) const {
            for (vector<AttributeExtractor*>::const_iterator i=m_extractors.begin(); i!=m_extractors.end(); ++i) {
                Locker locker(*i);
                (*i)->getAttributeIds(attributes);
            }
        }

    private:
        vector<AttributeExtractor*> m_extractors;
    };

    static const XMLCh _AttributeExtractor[] =  UNICODE_LITERAL_18(A,t,t,r,i,b,u,t,e,E,x,t,r,a,c,t,o,r);
    static const XMLCh _type[] =                UNICODE_LITERAL_4(t,y,p,e);

    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory DelegationAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory KeyDescriptorAttributeExtractorFactory;
    SHIBSP_DLLLOCAL PluginManager<AttributeExtractor,string,const DOMElement*>::Factory XMLAttributeExtractorFactory;
    AttributeExtractor* SHIBSP_DLLLOCAL ChainingExtractorFactory(const DOMElement* const & e)
    {
        return new ChainingAttributeExtractor(e);
    }
};

void SHIBSP_API shibsp::registerAttributeExtractors()
{
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(DELEGATION_ATTRIBUTE_EXTRACTOR, DelegationAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(KEYDESCRIPTOR_ATTRIBUTE_EXTRACTOR, KeyDescriptorAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(XML_ATTRIBUTE_EXTRACTOR, XMLAttributeExtractorFactory);
    SPConfig::getConfig().AttributeExtractorManager.registerFactory(CHAINING_ATTRIBUTE_EXTRACTOR, ChainingExtractorFactory);
}

ChainingAttributeExtractor::ChainingAttributeExtractor(const DOMElement* e)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _AttributeExtractor) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_extractors.push_back(conf.AttributeExtractorManager.newPlugin(type.get(),e));
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeExtractor.Chaining").error(
                    "caught exception processing embedded AttributeExtractor element: %s", ex.what()
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeExtractor);
    }
}

void ChainingAttributeExtractor::extractAttributes(
    const Application& application, const RoleDescriptor* issuer, const XMLObject& xmlObject, vector<Attribute*>& attributes
    ) const
{
    for (vector<AttributeExtractor*>::const_iterator i=m_extractors.begin(); i!=m_extractors.end(); ++i) {
        Locker locker(*i);
        (*i)->extractAttributes(application, issuer, xmlObject, attributes);
    }
}
