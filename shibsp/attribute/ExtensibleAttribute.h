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
#include <xmltooling/exceptions.h>

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
        ExtensibleAttribute(const std::vector<std::string>& ids, const char* formatter) : Attribute(ids) {
            m_obj = Attribute::marshall();
            m_obj.name("Extensible");
            m_obj.addmember("_formatter").string(formatter);
        }

        /**
         * Constructs based on a remoted ExtensibleAttribute.
         *
         * @param in    input object containing marshalled ExtensibleAttribute
         */
        ExtensibleAttribute(DDF& in) : Attribute(in), m_obj(in.copy()) {
        }

        virtual ~ExtensibleAttribute() {
            m_obj.destroy();
        }

        /**
         * Returns the set of values in a DDF list.
         *
         * @return  a mutable list object containing the values
         */
        DDF getValues() {
            return m_obj.first();
        }

        size_t valueCount() const {
            return m_obj.first().integer();
        }

        void clearSerializedValues() {
            m_serialized.clear();
        }

        const char* getString(size_t index) const {
            return m_obj.first()[static_cast<unsigned long>(index)].string();
        }

        const char* getScope(size_t index) const {
            return NULL;
        }

        void removeValue(size_t index) {
            Attribute::removeValue(index);
            DDF vals = m_obj.first();
            if (index < static_cast<size_t>(vals.integer()))
                vals[static_cast<unsigned long>(index)].remove().destroy();
        }

        const std::vector<std::string>& getSerializedValues() const;

        DDF marshall() const {
            if (!isCaseSensitive())
                m_obj.addmember("case_insensitive");
            if (isInternal())
                m_obj.addmember("internal");
            return m_obj.copy();
        }

    private:
        mutable DDF m_obj;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_nameidattr_h__ */
