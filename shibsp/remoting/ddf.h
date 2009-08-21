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
 * @file shibsp/remoting/ddf.h
 * 
 * C++ DDF abstraction for interpretive RPC
 */

#ifndef __ddf_h__
#define __ddf_h__

#include <shibsp/base.h>

#include <cstdio>
#include <iostream>

namespace shibsp {

    /**
     * DDF objects are implemented with a handle-body idiom and require explicit
     * destruction in order to allow stack objects to be freely mixed in structures
     * with heap objects. When stack objects leave scope, only the handle is freed.
     * Copying and assigning handle objects is a constant time operation equivalent
     * to a single pointer assignment, handled by compiler-generated behavior.
     */
    class SHIBSP_API DDF
    {
    public:
        /// @cond OFF
        // constructors
        DDF() : m_handle(NULL) {}
        DDF(const char* n);
        DDF(const char* n, const char* val, bool safe=true);
        DDF(const char* n, long val);
        DDF(const char* n, double val);
        DDF(const char* n, void* val);
    
        DDF& destroy();         // deep destructor
        DDF copy() const;       // deep copy routine
    
        // property accessors
        const char* name() const;           DDF& name(const char* n);
    
        // basic type checking
        bool isnull() const;
        bool isempty() const;
        bool isstring() const;
        bool isint() const;
        bool isfloat() const;
        bool isstruct() const;
        bool islist() const;
        bool ispointer() const;
    
        // type conversion and value extraction
        const char* string() const;     // legal for str
        long        integer() const;    // legal for all types
        double      floating() const;   // legal for float
        void*       pointer() const;    // legal for pointer
    
        // string helper methods
        size_t strlen() const;
        bool operator==(const char* s) const;
    
        // destructive node conversion methods
        DDF& empty();
        DDF& string(const char* val) {
            return string(const_cast<char*>(val), true);
        }
        DDF& unsafe_string(const char* val) {
            return string(const_cast<char*>(val), true, false);
        }
        DDF& string(char* val, bool copyit=true, bool safe=true);
        DDF& string(long val);
        DDF& string(double val);
        DDF& integer(long val);
        DDF& integer(const char* val);
        DDF& floating(double val);
        DDF& floating(const char* val);
        DDF& structure();
        DDF& list();
        DDF& pointer(void* val);
    
        // list/struct methods
        DDF& add(DDF& child);
        DDF& addbefore(DDF& child, DDF& before);
        DDF& addafter(DDF& child, DDF& after);
        void swap(DDF& arg);
        DDF& remove();
    
        // C-style iterators
        DDF parent() const;
        DDF first();
        DDF next();
        DDF last();
        DDF previous();
        
        // indexed operators
        DDF operator[](unsigned long index) const;
        DDF operator[](const char* path) const { return getmember(path); }
    
        // named member access/creation
        DDF addmember(const char* path);
        DDF getmember(const char* path) const;
    
        // debugging
        void dump(FILE* f=NULL, int indent=0) const;
    
        // serialization functions need private access
        friend SHIBSP_API std::ostream& operator<<(std::ostream& os, const DDF& obj);
        friend SHIBSP_API std::istream& operator>>(std::istream& is, DDF& obj);
        /// @endcond
    private:
        struct ddf_body_t* m_handle;
    };

    /**
     * Serializes a DDF object to a stream.
     * 
     * @param os    output stream
     * @param obj   DDF object to serialize
     * @return reference to the output stream
     */    
    SHIBSP_API std::ostream& operator<<(std::ostream& os, const DDF& obj);

    /**
     * Reconstitutes a DDF object from a stream.
     * 
     * @param is    input stream
     * @param obj   DDF object to reconstitute
     * @return reference to the input stream
     */
    SHIBSP_API std::istream& operator>>(std::istream& is, DDF& obj);
    
    /**
     * A "smart pointer" for disposing of DDF objects when they leave scope.
     */
    class SHIBSP_API DDFJanitor
    {
    public:
        DDFJanitor(DDF& obj) : m_obj(obj) {}
        ~DDFJanitor() { m_obj.destroy(); }
    private:
        DDF& m_obj;
        DDFJanitor(const DDFJanitor&);
        DDFJanitor& operator=(const DDFJanitor&);
    };

}

#endif // __ddf_h__
