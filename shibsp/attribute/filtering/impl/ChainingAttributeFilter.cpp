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
 * ChainingAttributeFilter.cpp
 * 
 * Chains together multiple AttributeFilter plugins.
 */

#include "internal.h"
#include "attribute/filtering/AttributeFilter.h"
#include "attribute/filtering/FilteringContext.h"

#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL ChainingAttributeFilter : public AttributeFilter
    {
    public:
        ChainingAttributeFilter(const DOMElement* e);
        virtual ~ChainingAttributeFilter() {
            for_each(m_filters.begin(), m_filters.end(), xmltooling::cleanup<AttributeFilter>());
        }
        
        Lockable* lock() {
            return this;
        }
        void unlock() {
        }
        
        void filterAttributes(const FilteringContext& context, vector<Attribute*>& attributes) const {
            for (vector<AttributeFilter*>::const_iterator i=m_filters.begin(); i!=m_filters.end(); ++i) {
                Locker locker(*i);
                (*i)->filterAttributes(context, attributes);
            }
        }

    private:
        vector<AttributeFilter*> m_filters;
    };

    static const XMLCh _AttributeFilter[] = UNICODE_LITERAL_15(A,t,t,r,i,b,u,t,e,F,i,l,t,e,r);
    static const XMLCh _type[] =            UNICODE_LITERAL_4(t,y,p,e);

    AttributeFilter* SHIBSP_DLLLOCAL ChainingAttributeFilterFactory(const DOMElement* const & e)
    {
        return new ChainingAttributeFilter(e);
    }
};

ChainingAttributeFilter::ChainingAttributeFilter(const DOMElement* e)
{
    SPConfig& conf = SPConfig::getConfig();

    // Load up the chain of handlers.
    e = e ? XMLHelper::getFirstChildElement(e, _AttributeFilter) : NULL;
    while (e) {
        auto_ptr_char type(e->getAttributeNS(NULL,_type));
        if (type.get() && *(type.get())) {
            try {
                m_filters.push_back(conf.AttributeFilterManager.newPlugin(type.get(),e));
            }
            catch (exception& ex) {
                Category::getInstance(SHIBSP_LOGCAT".AttributeFilter").error(
                    "caught exception processing embedded AttributeFilter element: %s", ex.what()
                    );
            }
        }
        e = XMLHelper::getNextSiblingElement(e, _AttributeFilter);
    }
}
