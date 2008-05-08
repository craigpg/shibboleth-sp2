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
 * @file shibsp/attribute/filtering/AttributeFilter.h
 * 
 * Engine for filtering attribute values.
 */

#ifndef __shibsp_attrfilt_h__
#define __shibsp_attrfilt_h__

#include <shibsp/attribute/filtering/FilteringContext.h>

#include <xmltooling/Lockable.h>

namespace shibsp {

    /**
     * Engine for filtering attribute values.
     */
    class SHIBSP_API AttributeFilter : public virtual xmltooling::Lockable
    {
        MAKE_NONCOPYABLE(AttributeFilter);
    protected:
        AttributeFilter() {}
    public:
        virtual ~AttributeFilter() {}

        /**
         * Filters values out of a set of attributes.
         * 
         * @param context       a FilteringContext interface
         * @param attributes    a mutable array containing the attributes to filter
         * 
         * @throws AttributeFileringException thrown if there is a problem filtering attributes
         */
        virtual void filterAttributes(const FilteringContext& context, std::vector<Attribute*>& attributes) const=0;
    };

    /**
     * Registers AttributeFilter classes into the runtime.
     */
    void SHIBSP_API registerAttributeFilters();

    /** AttributeFilter based on an XML mapping schema. */
    #define XML_ATTRIBUTE_FILTER "XML"

    /** AttributeFilter based on chaining together other filters. */
    #define CHAINING_ATTRIBUTE_FILTER "Chaining"
};

#endif /* __shibsp_attrfilt_h__ */
