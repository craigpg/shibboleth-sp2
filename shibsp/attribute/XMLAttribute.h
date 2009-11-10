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
 * @file shibsp/attribute/XMLAttribute.h
 *
 * An Attribute whose values are serialized XML.
 */

#ifndef __shibsp_xmlattr_h__
#define __shibsp_xmlattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

    /**
     * An Attribute whose values are serialized XML.
     */
    class SHIBSP_API XMLAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         *
         * @param ids   array with primary identifier in first position, followed by any aliases
         */
        XMLAttribute(const std::vector<std::string>& ids);

        /**
         * Constructs based on a remoted XMLAttribute.
         *
         * @param in    input object containing marshalled XMLAttribute
         */
        XMLAttribute(DDF& in);

        virtual ~XMLAttribute();

        /**
         * Returns the set of values encoded as XML.
         *
         * @return  a mutable vector of the values
         */
        std::vector<std::string>& getValues();

        /**
         * Returns the set of values encoded as XML.
         *
         * @return  an immutable vector of the values
         */
        const std::vector<std::string>& getValues() const;

        // Virtual function overrides.
        size_t valueCount() const;
        void clearSerializedValues();
        const char* getString(size_t index) const;
        void removeValue(size_t index);
        const std::vector<std::string>& getSerializedValues() const;
        DDF marshall() const;

    private:
        std::vector<std::string> m_values;
    };

};

#endif /* __shibsp_xmlattr_h__ */
