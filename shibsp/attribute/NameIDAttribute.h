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
 * @file shibsp/attribute/NameIDAttribute.h
 * 
 * An Attribute whose values are derived from or mappable to a SAML NameID.
 */

#ifndef __shibsp_nameidattr_h__
#define __shibsp_nameidattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /** Default serialization format for NameIDs */
    #define DEFAULT_NAMEID_FORMATTER    "$Name!!$NameQualifier!!$SPNameQualifier"

    /**
     * An Attribute whose values are derived from or mappable to a SAML NameID.
     */
    class SHIBSP_API NameIDAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids       array with primary identifier in first position, followed by any aliases
         * @param formatter template for serialization of tuple
         */
        NameIDAttribute(const std::vector<std::string>& ids, const char* formatter=DEFAULT_NAMEID_FORMATTER);

        /**
         * Constructs based on a remoted NameIDAttribute.
         * 
         * @param in    input object containing marshalled NameIDAttribute
         */
        NameIDAttribute(DDF& in);
        
        virtual ~NameIDAttribute();
        
        /**
         * Holds all the fields associated with a NameID.
         */
        struct SHIBSP_API Value
        {
            std::string m_Name;
            std::string m_Format;
            std::string m_NameQualifier;
            std::string m_SPNameQualifier;
            std::string m_SPProvidedID;
        };
        
        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * @return  a mutable vector of the values
         */
        std::vector<Value>& getValues();

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * @return  an immutable vector of the values
         */
        const std::vector<Value>& getValues() const;

        // Virtual function overrides.
        size_t valueCount() const;
        void clearSerializedValues();
        const char* getString(size_t index) const;
        const char* getScope(size_t index) const;
        void removeValue(size_t index);
        const std::vector<std::string>& getSerializedValues() const;
        DDF marshall() const;
    
    private:
        std::vector<Value> m_values;
        std::string m_formatter;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_nameidattr_h__ */
