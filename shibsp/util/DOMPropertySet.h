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
 * @file shibsp/util/DOMPropertySet.h
 * 
 * DOM-based property set implementation.
 */

#ifndef __shibsp_dompropset_h__
#define __shibsp_dompropset_h__

#include <shibsp/util/PropertySet.h>

#include <xmltooling/logging.h>

namespace shibsp {

    /**
     * DOM-based property set implementation.
     */
    class SHIBSP_API DOMPropertySet : public virtual PropertySet
    {
    public:
        DOMPropertySet();
        
        virtual ~DOMPropertySet();

        const PropertySet* getParent() const;
        void setParent(const PropertySet* parent);
        std::pair<bool,bool> getBool(const char* name, const char* ns=NULL) const;
        std::pair<bool,const char*> getString(const char* name, const char* ns=NULL) const;
        std::pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const;
        std::pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const;
        std::pair<bool,int> getInt(const char* name, const char* ns=NULL) const;
        void getAll(std::map<std::string,const char*>& properties) const;
        const PropertySet* getPropertySet(const char* name, const char* ns=shibspconstants::ASCII_SHIB2SPCONFIG_NS) const;
        const xercesc::DOMElement* getElement() const;

        /**
         * Loads the property set from a DOM element.
         * 
         * @param e         root element of property set
         * @param log       optional log object for tracing
         * @param filter    optional filter controls what child elements to include as nested PropertySets
         * @param remapper  optional map of property rename rules for legacy property support
         */
        void load(
            const xercesc::DOMElement* e,
            xmltooling::logging::Category* log=NULL,
            xercesc::DOMNodeFilter* filter=NULL,
            const std::map<std::string,std::string>* remapper=NULL
            );

    private:
        const PropertySet* m_parent;
        const xercesc::DOMElement* m_root;
        std::map<std::string,std::pair<char*,const XMLCh*> > m_map;
        std::map<std::string,DOMPropertySet*> m_nested;
    };

};

#endif /* __shibsp_dompropset_h__ */
