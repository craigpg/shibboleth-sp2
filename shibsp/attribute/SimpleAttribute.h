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
 * @file shibsp/attribute/SimpleAttribute.h
 * 
 * An Attribute whose values are simple strings.
 */

#ifndef __shibsp_simpattr_h__
#define __shibsp_simpattr_h__

#include <shibsp/attribute/Attribute.h>

namespace shibsp {

    /**
     * An Attribute whose values are simple strings.
     */
    class SHIBSP_API SimpleAttribute : public Attribute
    {
    public:
        /**
         * Constructor.
         * 
         * @param ids   array with primary identifier in first position, followed by any aliases
         */
        SimpleAttribute(const std::vector<std::string>& ids) : Attribute(ids) {}

        /**
         * Constructs based on a remoted SimpleAttribute.
         * 
         * @param in    input object containing marshalled SimpleAttribute
         */
        SimpleAttribute(DDF& in) : Attribute(in) {
            DDF val = in.first().first();
            while (val.string()) {
                m_serialized.push_back(val.string());
                val = in.first().next();
            }
        }
        
        virtual ~SimpleAttribute() {}

        /**
         * Returns the set of values encoded as UTF-8 strings.
         * 
         * <p>For simple values, the serialized form is just the actual string,
         * so the value array can be directly manipulated. 
         * 
         * @return  a mutable vector of the values
         */
        std::vector<std::string>& getValues() {
            return m_serialized;
        }
        
        void clearSerializedValues() {
            // Do nothing, since our values are already serialized.
        }
        
        DDF marshall() const {
            DDF ddf = Attribute::marshall();
            DDF vlist = ddf.first();
            for (std::vector<std::string>::const_iterator i=m_serialized.begin(); i!=m_serialized.end(); ++i)
                vlist.add(DDF(NULL).string(i->c_str()));
            return ddf;
        }
    };

};

#endif /* __shibsp_simpattr_h__ */
