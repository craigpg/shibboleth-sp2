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
 * @file shibsp/util/PropertySet.h
 * 
 * Interface to a generic set of typed properties or a DOM container of additional data.
 */

#ifndef __shibsp_propset_h__
#define __shibsp_propset_h__

#include <shibsp/util/SPConstants.h>
#include <map>
#include <xercesc/dom/DOM.hpp>

namespace shibsp {

    /**
     * Interface to a generic set of typed properties or a DOM container of additional data.
     */
    class SHIBSP_API PropertySet
    {
        MAKE_NONCOPYABLE(PropertySet);
    protected:
        PropertySet() {}
    public:
        virtual ~PropertySet() {}

        /**
         * Returns parent of this PropertySet, if any.
         *
         * @return the parent object, or NULL
         */
        virtual const PropertySet* getParent() const=0;

        /**
         * Establishes a "parent" PropertySet to supply inherited settings.
         *
         * @param parent    the parent PropertySet to use
         */
        virtual void setParent(const PropertySet* parent)=0;

        /**
         * Returns a boolean-valued property.
         * 
         * @param name  property name
         * @param ns    property namespace, or NULL
         * @return a pair consisting of a NULL indicator and the property value iff the indicator is true
         */
        virtual std::pair<bool,bool> getBool(const char* name, const char* ns=NULL) const=0;

        /**
         * Returns a string-valued property.
         * 
         * @param name  property name
         * @param ns    property namespace, or NULL
         * @return a pair consisting of a NULL indicator and the property value iff the indicator is true
         */
        virtual std::pair<bool,const char*> getString(const char* name, const char* ns=NULL) const=0;

        /**
         * Returns a Unicode string-valued property.
         * 
         * @param name  property name
         * @param ns    property namespace, or NULL
         * @return a pair consisting of a NULL indicator and the property value iff the indicator is true
         */
        virtual std::pair<bool,const XMLCh*> getXMLString(const char* name, const char* ns=NULL) const=0;

        /**
         * Returns an unsigned integer-valued property.
         * 
         * @param name  property name
         * @param ns    property namespace, or NULL
         * @return a pair consisting of a NULL indicator and the property value iff the indicator is true
         */
        virtual std::pair<bool,unsigned int> getUnsignedInt(const char* name, const char* ns=NULL) const=0;

        /**
         * Returns an integer-valued property.
         * 
         * @param name  property name
         * @param ns    property namespace, or NULL
         * @return a pair consisting of a NULL indicator and the property value iff the indicator is true
         */
        virtual std::pair<bool,int> getInt(const char* name, const char* ns=NULL) const=0;

        /**
         * Returns a map of all known properties in string form.
         *
         * @param properties    map to populate
         */
        virtual void getAll(std::map<std::string,const char*>& properties) const=0;

        /**
         * Returns a nested property set.
         * 
         * @param name  nested property set name
         * @param ns    nested property set namespace, or NULL
         * @return the nested property set, or NULL
         */        
        virtual const PropertySet* getPropertySet(const char* name, const char* ns=shibspconstants::ASCII_SHIB2SPCONFIG_NS) const=0;
        
        /**
         * Returns a DOM element representing the property container, if any.
         * 
         * @return a DOM element, or NULL
         */
        virtual const xercesc::DOMElement* getElement() const=0;
    };
};

#endif /* __shibsp_propset_h__ */
