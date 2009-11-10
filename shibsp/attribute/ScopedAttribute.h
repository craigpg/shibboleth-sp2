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
 * @file shibsp/attribute/ScopedAttribute.h
 * 
 * An Attribute whose values are relations of a value and a scope.
 */

#ifndef __shibsp_scopedattr_h__
#define __shibsp_scopedattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4251 )
#endif

    /**
     * An Attribute whose values are relations of a value and a scope.
     * 
     * <p>In practice, scoped attributes are simple pairs of strings instead
     * of a single string. They can be expressed as a string easily using a delimeter,
     * typically an '@' symbol. The scope concept allows certain kinds of filtering to
     * be performed more intelligently and efficiently, although not all scoped
     * attributes can be effectively filtered (e.g. if the set of scope values is
     * unconstrained).
     */
    class SHIBSP_API ScopedAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids   array with primary identifier in first position, followed by any aliases
         * @param delimeter value/scope delimeter when serializing
         */
        ScopedAttribute(const std::vector<std::string>& ids, char delimeter='@');

        /**
         * Constructs based on a remoted ScopedAttribute.
         * 
         * @param in    input object containing marshalled ScopedAttribute
         */
        ScopedAttribute(DDF& in);
        
        virtual ~ScopedAttribute();

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * <p>Each compound value is a pair containing the simple value and the scope. 
         * 
         * @return  a mutable vector of the values
         */
        std::vector< std::pair<std::string,std::string> >& getValues();

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * <p>Each compound value is a pair containing the simple value and the scope. 
         * 
         * @return  an immutable vector of the values
         */
        const std::vector< std::pair<std::string,std::string> >& getValues() const;

        // Virtual function overrides.
        size_t valueCount() const;
        void clearSerializedValues();
        const char* getString(size_t index) const;
        const char* getScope(size_t index) const;
        void removeValue(size_t index);
        const std::vector<std::string>& getSerializedValues() const;
        DDF marshall() const;
    
    private:
        char m_delimeter;
        std::vector< std::pair<std::string,std::string> > m_values;
    };

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

};

#endif /* __shibsp_scopedattr_h__ */
