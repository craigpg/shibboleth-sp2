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
 * MetadataExtSchemaValidators.cpp
 * 
 * Schema-based validators for Shibboleth metadata extension classes
 */

#include "internal.h"
#include "exceptions.h"
#include "metadata/MetadataExt.h"

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xmltooling/validation/ValidatorSuite.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmltooling;
using namespace std;

using shibspconstants::SHIBMD_NS;

namespace shibsp {
    XMLOBJECTVALIDATOR_SIMPLE(SHIBSP_DLLLOCAL,Scope);

    BEGIN_XMLOBJECTVALIDATOR(SHIBSP_DLLLOCAL,KeyAuthority);
        XMLOBJECTVALIDATOR_NONEMPTY(KeyAuthority,KeyInfo);
    END_XMLOBJECTVALIDATOR;
    
    SHIBSP_DLLLOCAL PluginManager<MetadataProvider,string,const DOMElement*>::Factory DynamicMetadataProviderFactory;
};

#define REGISTER_ELEMENT(cname) \
    q=QName(SHIBMD_NS,cname::LOCAL_NAME); \
    XMLObjectBuilder::registerBuilder(q,new cname##Builder()); \
    SchemaValidators.registerValidator(q,new cname##SchemaValidator())
    
void shibsp::registerMetadataExtClasses() {
    QName q;
    REGISTER_ELEMENT(Scope);
    REGISTER_ELEMENT(KeyAuthority);

    opensaml::SAMLConfig::getConfig().MetadataProviderManager.registerFactory(DYNAMIC_METADATA_PROVIDER, DynamicMetadataProviderFactory);
}
