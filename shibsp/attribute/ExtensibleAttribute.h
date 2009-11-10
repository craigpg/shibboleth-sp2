/*
 *  Copyright 2009 Internet2
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
 * @file shibsp/attribute/ExtensibleAttribute.h
 *
 * An Attribute whose values are arbitrary structures.
 */

#ifndef __shibsp_extattr_h__
#define __shibsp_extattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * An Attribute whose values are arbitrary structures.
     */
    class SHIBSP_API ExtensibleAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         *
         * @param ids       array with primary identifier in first position, followed by any aliases
         * @param formatter template for serialization of values
         */
        ExtensibleAttribute(const std::vector<std::string>& ids, const char* formatter);

        /**
         * Constructs based on a remoted ExtensibleAttribute.
         *
         * @param in    input object containing marshalled ExtensibleAttribute
         */
        ExtensibleAttribute(DDF& in);

        virtual ~ExtensibleAttribute();

        /**
         * Returns the set of values in a DDF list.
         *
         * @return  a mutable list object containing the values
         */
        DDF getValues();

        // Virtual function overrides.
        size_t valueCount() const;
        void clearSerializedValues();
        const char* getString(size_t index) const;
        const char* getScope(size_t index) const;
        void removeValue(size_t index);
        const std::vector<std::string>& getSerializedValues() const;
        DDF marshall() const;

    private:
        mutable DDF m_obj;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_nameidattr_h__ */
