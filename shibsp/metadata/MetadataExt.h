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
 * @file shibsp/metadata/MetadataExt.h
 * 
 * XMLObjects representing Shibboleth metadata extensions.
 */

#ifndef __shibsp_metaext_h__
#define __shibsp_metaext_h__

#include <shibsp/util/SPConstants.h>

#include <xmltooling/AttributeExtensibleXMLObject.h>
#include <xmltooling/ConcreteXMLObjectBuilder.h>
#include <xmltooling/util/XMLObjectChildrenList.h>

#define DECL_SHIBOBJECTBUILDER(cname) \
    DECL_XMLOBJECTBUILDER(SHIBSP_API,cname,shibspconstants::SHIBMD_NS,shibspconstants::SHIBMD_PREFIX)

namespace xmlsignature {
    class XMLTOOL_API KeyInfo;
};

namespace shibsp {

    BEGIN_XMLOBJECT(SHIBSP_API,Scope,xmltooling::XMLObject,Scope element);
        DECL_BOOLEAN_ATTRIB(Regexp,REGEXP,false);
        DECL_SIMPLE_CONTENT(Value);
    END_XMLOBJECT;

    BEGIN_XMLOBJECT(SHIBSP_API,KeyAuthority,xmltooling::AttributeExtensibleXMLObject,KeyAuthority element);
        DECL_INTEGER_ATTRIB(VerifyDepth,VERIFYDEPTH);
        DECL_TYPED_FOREIGN_CHILDREN(KeyInfo,xmlsignature);
    END_XMLOBJECT;

    DECL_SHIBOBJECTBUILDER(Scope);
    DECL_SHIBOBJECTBUILDER(KeyAuthority);
    
    /**
     * Registers builders and validators for Shibboleth metadata extension classes into the runtime.
     */
    void SHIBSP_API registerMetadataExtClasses();
};

#endif /* __shibsp_metaext_h__ */
