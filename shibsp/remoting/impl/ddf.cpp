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
 * ddf.cpp
 *
 * C++ DDF abstraction for interpretive RPC
 */

#include "internal.h"
#include "remoting/ddf.h"

#ifdef WIN32
# define snprintf _snprintf
#endif

#include <stdexcept>
#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/URLEncoder.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

// defensive string functions

size_t ddf_strlen(const char* s)
{
    return s ? strlen(s) : 0;
}

char* ddf_strdup(const char* s)
{
    return (s && *s) ? strdup(s) : NULL;
}

#define MAX_NAME_LEN 255

/* Parses '.' notation paths, where each component is at most MAX_NAME_LEN long.
   path contains the address of a constant string which is the current path.
   name points to a buffer in which to place the first path component.
   After execution, the path pointer will be moved past the first dot.
   The actual path string is never modified. Only name is written to.
   The name buffer is returned from the function. */
char* ddf_token(const char** path, char* name)
{
    *name=0;
    if (*path==NULL || **path==0)
        return name;

    const char* temp=strchr(*path,'.');
    if (temp==NULL) {
        strncpy(name,*path,MAX_NAME_LEN);
        name[MAX_NAME_LEN]=0;
        *path=NULL;
    }
    else if (temp>*path) {
        strncpy(name,*path,temp-*path);
        name[temp-*path]=0;
        *path=temp+1;
    }
    else
        *path=temp+1;
    return name;
}

// body implementation

struct shibsp::ddf_body_t {
    ddf_body_t() : name(NULL), parent(NULL), next(NULL), prev(NULL), type(DDF_EMPTY) {}

    char* name;                     // name of node
    ddf_body_t* parent;             // parent node, if any
    ddf_body_t* next;               // next node, if any
    ddf_body_t* prev;               // previous node, if any

    enum {
	    DDF_EMPTY,
	    DDF_STRING,
	    DDF_INT,
        DDF_FLOAT,
	    DDF_STRUCT,
        DDF_LIST,
	    DDF_POINTER,
        DDF_STRING_UNSAFE
    } type;                         // data type of node

    union {
        char* string;
        long integer;
        double floating;
        void* pointer;
        struct {
	        ddf_body_t* first;
	        ddf_body_t* last;
	        ddf_body_t* current;
	        unsigned long count;
        } children;
    } value;                        // value of node
};

// library implementation

DDF::DDF() : m_handle(NULL)
{
}

DDF::DDF(const char* n)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
}

DDF::DDF(const char* n, const char* val, bool safe)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    string(const_cast<char*>(val), true, safe);
}

DDF::DDF(const char* n, long val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    integer(val);
}

DDF::DDF(const char* n, double val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    floating(val);
}

DDF::DDF(const char* n, void* val)
{
    m_handle=new(nothrow) ddf_body_t;
    name(n);
    pointer(val);
}

DDF& DDF::destroy()
{
    remove().empty().name(NULL);
    delete m_handle;
    m_handle=NULL;
    return *this;
}

DDF DDF::copy() const
{
    if (m_handle==NULL)
        return DDF();

    switch (m_handle->type) {
        case ddf_body_t::DDF_EMPTY:
            return DDF(m_handle->name);
        case ddf_body_t::DDF_STRING:
        case ddf_body_t::DDF_STRING_UNSAFE:
            return DDF(m_handle->name,m_handle->value.string,(m_handle->type==ddf_body_t::DDF_STRING));
        case ddf_body_t::DDF_INT:
            return DDF(m_handle->name,m_handle->value.integer);
        case ddf_body_t::DDF_FLOAT:
            return DDF(m_handle->name,m_handle->value.floating);
        case ddf_body_t::DDF_POINTER:
            return DDF(m_handle->name,m_handle->value.pointer);
        case ddf_body_t::DDF_STRUCT:
        case ddf_body_t::DDF_LIST:
        {
            DDF copy(m_handle->name), temp;
            if (m_handle->type==ddf_body_t::DDF_STRUCT)
                copy.structure();
            else
                copy.list();
            ddf_body_t* child=m_handle->value.children.first;
            while (child) {
                temp.m_handle=child;
                DDF temp2=temp.copy();
                copy.add(temp2);
                if (copy.m_handle==NULL)
                    return copy;
                if (m_handle->value.children.current==child)
                    copy.m_handle->value.children.current=copy.m_handle->value.children.last;
                child=child->next;
            }
            return copy;
        }
    }
    return DDF();
}

const char* DDF::name() const
{
    return (m_handle) ? m_handle->name : NULL;
}

DDF& DDF::name(const char* name)
{
    char trunc_name[MAX_NAME_LEN+1]="";

    if (m_handle) {
        if (m_handle->name)
            free(m_handle->name);
        if (name && *name) {
            strncpy(trunc_name,name,MAX_NAME_LEN);
            trunc_name[MAX_NAME_LEN]='\0';
            m_handle->name=ddf_strdup(trunc_name);
            if (!m_handle->name)
                destroy();
        }
        else
            m_handle->name=NULL;
    }
    return *this;
}

bool DDF::isnull() const
{
    return m_handle ? false : true;
}

bool DDF::isempty() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_EMPTY) : false;
}

bool DDF::isstring() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_STRING || m_handle->type==ddf_body_t::DDF_STRING_UNSAFE) : false;
}

bool DDF::isint() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_INT) : false;
}

bool DDF::isfloat() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_FLOAT) : false;
}

bool DDF::isstruct() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_STRUCT) : false;
}

bool DDF::islist() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_LIST) : false;
}

bool DDF::ispointer() const
{
    return m_handle ? (m_handle->type==ddf_body_t::DDF_POINTER) : false;
}

const char* DDF::string() const
{
    return isstring() ? m_handle->value.string : NULL;
}

long DDF::integer() const
{
    if (m_handle) {
        switch(m_handle->type) {
            case ddf_body_t::DDF_INT:
                return m_handle->value.integer;
            case ddf_body_t::DDF_FLOAT:
                return static_cast<long>(m_handle->value.floating);
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                return m_handle->value.string ? atol(m_handle->value.string) : 0;
            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
                return m_handle->value.children.count;
        }
    }
    return 0;
}

double DDF::floating() const
{
    if (m_handle) {
        switch(m_handle->type) {
            case ddf_body_t::DDF_INT:
                return m_handle->value.integer;
            case ddf_body_t::DDF_FLOAT:
                return m_handle->value.floating;
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                return m_handle->value.string ? atof(m_handle->value.string) : 0;
            case ddf_body_t::DDF_STRUCT:
            case ddf_body_t::DDF_LIST:
                return m_handle->value.children.count;
        }
    }
    return 0;
}

void* DDF::pointer() const
{
    return ispointer() ? m_handle->value.pointer : NULL;
}

size_t DDF::strlen() const
{
    return ddf_strlen(string());
}

bool DDF::operator==(const char* s) const
{
    if (string()==NULL || s==NULL)
        return (string()==NULL && s==NULL);
    else
        return (::strcmp(string(),s)==0);
}

DDF& DDF::empty()
{
    if (m_handle) {
        switch (m_handle->type) {
            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                if (m_handle->value.string)
                    free(m_handle->value.string);
                break;
            case ddf_body_t::DDF_LIST:
            case ddf_body_t::DDF_STRUCT:
            {
                DDF temp;
                while (m_handle->value.children.first)
                {
                    temp.m_handle=m_handle->value.children.first;
                    temp.destroy();
                }
            }
        }
        m_handle->type=ddf_body_t::DDF_EMPTY;
    }
    return *this;
}

DDF& DDF::string(char* val, bool copyit, bool safe)
{
    if (empty().m_handle) {
        m_handle->value.string = copyit ? ddf_strdup(val) : val;
        if (!m_handle->value.string && val && *val)
            return destroy();
        m_handle->type=(safe ? ddf_body_t::DDF_STRING : ddf_body_t::DDF_STRING_UNSAFE);
    }
    return *this;
}

DDF& DDF::string(const char* val)
{
    return string(const_cast<char*>(val), true);
}

DDF& DDF::unsafe_string(const char* val)
{
    return string(const_cast<char*>(val), true, false);
}

DDF& DDF::string(long val)
{
    char buf[20];

    sprintf(buf,"%ld",val);
    return string(buf);
}

DDF& DDF::string(double val)
{
    char buf[40];

    snprintf(buf,39,"%f",val);
    return string(buf);
}

DDF& DDF::integer(long val)
{
    if (empty().m_handle) {
        m_handle->value.integer=val;
        m_handle->type=ddf_body_t::DDF_INT;
    }
    return *this;
}

DDF& DDF::integer(const char* val)
{
    if (empty().m_handle) {
        m_handle->value.integer=(val ? atol(val) : 0);
        m_handle->type=ddf_body_t::DDF_INT;
    }
    return *this;
}

DDF& DDF::floating(double val)
{
    if (empty().m_handle) {
        m_handle->value.floating=val;
        m_handle->type=ddf_body_t::DDF_FLOAT;
    }
    return *this;
}

DDF& DDF::floating(const char* val)
{
    if (empty().m_handle) {
        m_handle->value.floating=(val ? atof(val) : 0);
        m_handle->type=ddf_body_t::DDF_FLOAT;
    }
    return *this;
}

DDF& DDF::structure()
{
    if (empty().m_handle) {
        m_handle->type=ddf_body_t::DDF_STRUCT;
        m_handle->value.children.first=NULL;
        m_handle->value.children.last=NULL;
        m_handle->value.children.current=NULL;
        m_handle->value.children.count=0;
    }
    return *this;
}

DDF& DDF::list()
{
    if (empty().m_handle) {
        m_handle->type=ddf_body_t::DDF_LIST;
        m_handle->value.children.first=NULL;
        m_handle->value.children.last=NULL;
        m_handle->value.children.current=NULL;
        m_handle->value.children.count=0;
    }
    return *this;
}

DDF& DDF::pointer(void* val)
{
    if (empty().m_handle) {
        m_handle->value.pointer=val;
        m_handle->type=ddf_body_t::DDF_POINTER;
    }
    return *this;
}

DDF& DDF::add(DDF& child)
{
    if ((!isstruct() && !islist()) || !child.m_handle)
        return child;

    if (m_handle==child.m_handle->parent)
        return child;

    if (isstruct()) {
        if (!child.name())
            return child;
        getmember(child.name()).destroy();
    }

    child.remove();
    if (!m_handle->value.children.first)
        m_handle->value.children.first=child.m_handle;
    else {
        m_handle->value.children.last->next=child.m_handle;
        child.m_handle->prev=m_handle->value.children.last;
    }
    m_handle->value.children.last=child.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

DDF& DDF::addbefore(DDF& child, DDF& before)
{
    if (!islist() || !child.m_handle || !before.m_handle || before.m_handle->parent!=m_handle)
        return child;

    child.remove();
    if (m_handle->value.children.first==before.m_handle)
        m_handle->value.children.first=child.m_handle;
    child.m_handle->prev=before.m_handle->prev;
    if (child.m_handle->prev)
        child.m_handle->prev->next=child.m_handle;
    before.m_handle->prev=child.m_handle;
    child.m_handle->next=before.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

DDF& DDF::addafter(DDF& child, DDF& after)
{
    if (!islist() || !child.m_handle || !after.m_handle || after.m_handle->parent!=m_handle)
        return child;

    child.remove();
    if (m_handle->value.children.last==after.m_handle)
        m_handle->value.children.last=child.m_handle;
    child.m_handle->next=after.m_handle->next;
    if (child.m_handle->next)
        child.m_handle->next->prev=child.m_handle;
    after.m_handle->next=child.m_handle;
    child.m_handle->prev=after.m_handle;
    child.m_handle->parent=m_handle;
    m_handle->value.children.count++;
    return child;
}

void DDF::swap(DDF& arg)
{
    ddf_body_t* temp=arg.m_handle;
    arg.m_handle=m_handle;
    m_handle=temp;
}

DDF& DDF::remove()
{
    if (!m_handle || !m_handle->parent)
        return *this;

    if (m_handle->next)
        m_handle->next->prev=m_handle->prev;

    if (m_handle->prev)
        m_handle->prev->next=m_handle->next;

    if (m_handle->parent->value.children.first==m_handle)
        m_handle->parent->value.children.first=m_handle->next;

    if (m_handle->parent->value.children.last==m_handle)
        m_handle->parent->value.children.last=m_handle->prev;

    if (m_handle->parent->value.children.current==m_handle)
        m_handle->parent->value.children.current=m_handle->prev;

    m_handle->parent->value.children.count--;
    m_handle->parent=NULL;
    m_handle->next=NULL;
    m_handle->prev=NULL;
    return *this;
}

DDF DDF::parent() const
{
    DDF p;

    p.m_handle=(m_handle ? m_handle->parent : NULL);
    return p;
}

DDF DDF::first()
{
    DDF f;

    if (islist() || isstruct())
        f.m_handle=m_handle->value.children.current=m_handle->value.children.first;
    return f;
}

DDF DDF::next()
{
    DDF n;

    if ((islist() || isstruct()) && m_handle->value.children.current!=m_handle->value.children.last) {
        if (!m_handle->value.children.current)
            n.m_handle=m_handle->value.children.current=m_handle->value.children.first;
        else
            n.m_handle=m_handle->value.children.current=m_handle->value.children.current->next;
    }
    return n;
}

DDF DDF::last()
{
    DDF l;

    if ((islist() || isstruct()) && m_handle->value.children.last) {
        m_handle->value.children.current=m_handle->value.children.last->prev;
        l.m_handle=m_handle->value.children.last;
    }
    return l;
}

DDF DDF::previous()
{
    DDF p;

    if (islist() || isstruct()) {
        p.m_handle=m_handle->value.children.current;
        if (p.m_handle)
            m_handle->value.children.current=m_handle->value.children.current->prev;
    }
    return p;
}

DDF DDF::operator[](const char* path) const
{
    return getmember(path);
}

DDF DDF::operator[](unsigned long index) const
{
    DDF d;

    if (islist() && index<m_handle->value.children.count) {
        for (d.m_handle=m_handle->value.children.first; index; index--)
            d.m_handle=d.m_handle->next;
    }
    else
        throw range_error("DDF object not a list with >=index+1 elements");
    return d;
}

DDF DDF::addmember(const char* path)
{
    char name[MAX_NAME_LEN+1];
    const char* path_ptr=path;

    if (m_handle && ddf_strlen(ddf_token(&path_ptr,name))>0) {
        if (!isstruct())
            structure();

        DDF new_member=getmember(name);
        if (!new_member.m_handle) {
            DDF temp(name);
            new_member=add(temp);
        }

        if (new_member.m_handle) {
            if (ddf_strlen(path_ptr)>0) {
                DDF last_member=new_member.addmember(path_ptr);
                if (!last_member.m_handle)
                    return new_member.destroy();
                else
                    return last_member;
            }
            return new_member;
        }
        return new_member;
    }
    return DDF();
}

DDF DDF::getmember(const char* path) const
{
    DDF current;
    char name[MAX_NAME_LEN+1];
    const char* path_ptr=path;

    ddf_token(&path_ptr, name);
    if (*name == 0)
        return current;
    else if (*name == '[') {
        unsigned long i = strtoul(name+1, NULL, 10);
        if (islist() && i < m_handle->value.children.count)
            current=operator[](i);
        else if (i == 0)
            current = *this;
    }
    else if (isstruct()) {
        current.m_handle = m_handle->value.children.first;
        while (current.m_handle && strcmp(current.m_handle->name,name) != 0)
            current.m_handle = current.m_handle->next;
    }
    else if (islist()) {
        current.m_handle = m_handle->value.children.first;
        return current.getmember(path);
    }

    if (current.m_handle && path_ptr && *path_ptr)
        current = current.getmember(path_ptr);
    return current;
}


void ddf_print_indent(FILE* f, int indent)
{
    for (; indent>0; indent--)
        putc(' ',f);
}

void DDF::dump(FILE* f, int indent) const
{
    if (!f)
        f=stderr;

    ddf_print_indent(f,indent);
    if (m_handle) {
        switch (m_handle->type) {

            case ddf_body_t::DDF_EMPTY:
                fprintf(f,"empty");
                if (m_handle->name)
                    fprintf(f," %s",m_handle->name);
                break;

            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                if (m_handle->name)
                    fprintf(f,"char* %s = ",m_handle->name);
                else
                    fprintf(f,"char* = ");
                if (const char* chptr=m_handle->value.string) {
                    putc('"',f);
                    while (*chptr)
                        fputc(*chptr++,f);
                    putc('"',f);
                }
                else
                    fprintf(f,"NULL");
                break;

            case ddf_body_t::DDF_INT:
                if (m_handle->name)
                    fprintf(f,"long %s = ",m_handle->name);
                else
                    fprintf(f,"long = ");
                fprintf(f,"%ld",m_handle->value.integer);
                break;

            case ddf_body_t::DDF_FLOAT:
                if (m_handle->name)
                    fprintf(f,"double %s = ",m_handle->name);
                else
                    fprintf(f,"double = ");
                fprintf(f,"%.15f",m_handle->value.floating);
                break;

            case ddf_body_t::DDF_STRUCT:
                fprintf(f,"struct ");
                if (m_handle->name)
                    fprintf(f,"%s ",m_handle->name);
                putc('{',f);
                if (m_handle->value.children.count) {
                    putc('\n',f);
                    DDF child;
                    child.m_handle=m_handle->value.children.first;
                    while (child.m_handle) {
                        child.dump(f,indent+2);
                        child.m_handle=child.m_handle->next;
                    }
                }
                ddf_print_indent(f,indent);
                putc('}',f);
                break;

            case ddf_body_t::DDF_LIST:
                fprintf(f,"list");
                if (m_handle->name)
                    fprintf(f," %s",m_handle->name);
                fprintf(f,"[%lu] {",m_handle->value.children.count);
                if (m_handle->value.children.count) {
                    putc('\n',f);
                    DDF child;
                    child.m_handle=m_handle->value.children.first;
                    while (child.m_handle) {
                        child.dump(f,indent+2);
                        child.m_handle=child.m_handle->next;
                    }
                }
                ddf_print_indent(f,indent);
                putc('}',f);
                break;

            case ddf_body_t::DDF_POINTER:
                if (m_handle->name)
                    fprintf(f,"void* %s = ",m_handle->name);
                else
                    fprintf(f,"void* = ");
                if (m_handle->value.pointer)
                    fprintf(f,"%p",m_handle->value.pointer);
                else
                    fprintf(f,"NULL");
                break;

            default:
                fprintf(f,"UNKNOWN -- WARNING: ILLEGAL VALUE");
        }
    }
    else
        fprintf(f,"NULL");
    fprintf(f,";\n");
}

// Serialization is fairly easy. We have to walk the DDF and hand-generate a
// wddxPacket XML fragment, with some simple extensions. We escape the four major
// special characters, which requires that we output strings one char at a time.

void xml_encode(ostream& os, const char* start)
{
    size_t pos;
    while (start && *start) {
        pos = strcspn(start, "\"<>&");
        if (pos > 0) {
            os.write(start,pos);
            start += pos;
        }
        else {
            switch (*start) {
                case '"':   os << "&quot;";     break;
                case '<':   os << "&lt;";       break;
                case '>':   os << "&gt;";       break;
                case '&':   os << "&amp;";      break;
                default:    os << *start;
            }
            start++;
        }
    }
}

void serialize(ddf_body_t* p, ostream& os, bool name_attr=true)
{
    if (p) {
        switch (p->type) {

            case ddf_body_t::DDF_STRING:
            case ddf_body_t::DDF_STRING_UNSAFE:
                os << "<string";
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                if (p->value.string) {
                    if (p->type == ddf_body_t::DDF_STRING) {
                        os << '>';
                        xml_encode(os,p->value.string);
                    }
                    else {
                        os << " unsafe=\"1\">";
                        xml_encode(os,XMLToolingConfig::getConfig().getURLEncoder()->encode(p->value.string).c_str());
                    }
                    os << "</string>";
                }
                else
                    os << "/>";
                break;

            case ddf_body_t::DDF_INT:
                os << "<number";
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                os << '>' << p->value.integer << "</number>";
                break;

            case ddf_body_t::DDF_FLOAT:
                os << "<number";
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                os << '>' << fixed << p->value.floating << dec << "</number>";
                break;

            case ddf_body_t::DDF_STRUCT:
            {
                os << "<struct";
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                os << '>';
                ddf_body_t* child=p->value.children.first;
                while (child) {
                    os << "<var name=\"";
                    xml_encode(os,child->name);
                    os << "\">";
                    serialize(child,os,false);
                    os << "</var>";
                    child=child->next;
                }
                os << "</struct>";
                break;
            }

            case ddf_body_t::DDF_LIST:
            {
                os << "<array length=\"" << p->value.children.count << '"';
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                os << '>';
                ddf_body_t* child=p->value.children.first;
                while (child) {
                    serialize(child,os);
                    child=child->next;
                }
                os << "</array>";
                break;
            }

            case ddf_body_t::DDF_EMPTY:
            case ddf_body_t::DDF_POINTER:
            default:
                os << "<null";
                if (name_attr && p->name) {
                    os << " name=\"";
                    xml_encode(os,p->name);
                    os << '"';
                }
                os << "/>";
                break;
        }
    }
    else
        os << "<null/>";
}

// The stream insertion will work for any ostream-based object.

SHIBSP_API ostream& shibsp::operator<<(ostream& os, const DDF& obj)
{
    os.precision(15);
    os << "<wddxPacket version=\"1.0\" lowercase=\"no\"><header/><data>";
    serialize(obj.m_handle,os);
    os << "</data></wddxPacket>";
    return os;
}

// This is a DTD internal subset based on a compatible permutation of the WDDX spec, with the
// extension of a name attribute on all the typed elements, which DDF has, but WDDX does not.

/*
static const char* g_DocType=
"\
<!DOCTYPE wddxPacket [\n\
<!ELEMENT wddxPacket (header, data)>\n\
<!ATTLIST wddxPacket version CDATA #FIXED \"1.0\" lowercase (yes|no) \"yes\">\n\
<!ELEMENT header (comment?)>\n\
<!ELEMENT comment (#PCDATA)>\n\
<!ELEMENT data (null | number | string | array | struct)>\n\
<!ELEMENT null EMPTY>\n\
<!ATTLIST null name CDATA #IMPLIED type CDATA #IMPLIED>\n\
<!ELEMENT string (#PCDATA | char)*>\n\
<!ATTLIST string name CDATA #IMPLIED type CDATA #IMPLIED>\n\
<!ELEMENT char EMPTY>\n\
<!ATTLIST char code CDATA #REQUIRED>\n\
<!ELEMENT number (#PCDATA)>\n\
<!ATTLIST number name CDATA #IMPLIED type CDATA #IMPLIED>\n\
<!ELEMENT array (null | number | string | array | struct)*>\n\
<!ATTLIST array length CDATA #REQUIRED name CDATA #IMPLIED type CDATA #IMPLIED>\n\
<!ELEMENT struct (var*)>\n\
<!ATTLIST struct name CDATA #IMPLIED type CDATA #IMPLIED>\n\
<!ELEMENT var (null | number | string | array | struct)>\n\
<!ATTLIST var name CDATA #REQUIRED>\n\
]>\n";
*/

// This function constructs a DDF object equivalent to the wddx data element rooted
// by the input.

static const XMLCh _no[] =      UNICODE_LITERAL_2(n,o);
static const XMLCh _name[] =    UNICODE_LITERAL_4(n,a,m,e);
static const XMLCh _var[] =     UNICODE_LITERAL_3(v,a,r);
static const XMLCh _string[] =  UNICODE_LITERAL_6(s,t,r,i,n,g);
static const XMLCh _number[] =  UNICODE_LITERAL_6(n,u,m,b,e,r);
static const XMLCh _array[] =   UNICODE_LITERAL_5(a,r,r,a,y);
static const XMLCh _struct[] =  UNICODE_LITERAL_6(s,t,r,u,c,t);
static const XMLCh _lowercase[] = UNICODE_LITERAL_9(l,o,w,e,r,c,a,s,e);
static const XMLCh _unsafe[] =  UNICODE_LITERAL_6(u,n,s,a,f,e);

DDF deserialize(DOMElement* root, bool lowercase)
{
    DDF obj(NULL);
    auto_ptr_char name_val(root->getAttributeNS(NULL, _name));
    if (name_val.get() && *name_val.get()) {
        if (lowercase)
            for (char* pch=const_cast<char*>(name_val.get()); *pch=tolower(*pch); pch++);
        obj.name(name_val.get());
    }

    const XMLCh* tag=root->getTagName();
    if (XMLString::equals(tag,_var)) {
        root=XMLHelper::getFirstChildElement(root);
        tag=(root ? root->getTagName() : &chNull);
    }

    if (XMLString::equals(tag,_string)) {
        DOMNode* child=root->getFirstChild();
        if (child && child->getNodeType()==DOMNode::TEXT_NODE) {
            const XMLCh* unsafe = root->getAttributeNS(NULL, _unsafe);
            if (unsafe && *unsafe==chDigit_1) {
                // If it's unsafe, it's not UTF-8 data, so we have to convert to ASCII and decode it.
                char* encoded = XMLString::transcode(child->getNodeValue());
                XMLToolingConfig::getConfig().getURLEncoder()->decode(encoded);
                obj.string(encoded, true, false); // re-copy into free-able buffer, plus mark unsafe
                XMLString::release(&encoded);
            }
            else {
                char* val = toUTF8(child->getNodeValue(), true);    // use malloc
                obj.string(val, false); // don't re-copy the string
            }
        }
    }
    else if (XMLString::equals(tag,_number)) {
        DOMNode* child=root->getFirstChild();
        if (child && child->getNodeType()==DOMNode::TEXT_NODE) {
            auto_ptr_char val(child->getNodeValue());
            if (val.get() && strchr(val.get(),'.'))
                obj.floating(val.get());
            else
                obj.integer(val.get());
        }
    }
    else if (XMLString::equals(tag,_array)) {
        obj.list();
        DOMNodeList* children=root->getChildNodes();
        for (unsigned int i=0; children && i<children->getLength(); i++)
            if (children->item(i)->getNodeType()==DOMNode::ELEMENT_NODE) {
                DDF temp=deserialize(static_cast<DOMElement*>(children->item(i)),lowercase);
                obj.add(temp);
            }
    }
    else if (XMLString::equals(tag,_struct)) {
        obj.structure();
        DOMNodeList* children=root->getChildNodes();
        for (unsigned int i=0; children && i<children->getLength(); i++)
            if (children->item(i)->getNodeType()==DOMNode::ELEMENT_NODE) {
                DDF temp=deserialize(static_cast<DOMElement*>(children->item(i)),lowercase);
                obj.add(temp);
            }
    }

    return obj;
}

SHIBSP_API istream& shibsp::operator>>(istream& is, DDF& obj)
{
    // Parse the input stream into a DOM tree and construct the equivalent DDF.
    DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(is);
    XercesJanitor<DOMDocument> docj(doc);
    const XMLCh* lowercase=doc->getDocumentElement()->getAttribute(_lowercase);
    DOMElement* first=XMLHelper::getFirstChildElement(XMLHelper::getLastChildElement(doc->getDocumentElement()));
    obj.destroy();
    obj=deserialize(first,XMLString::compareString(lowercase,_no)!=0);
    return is;
}
