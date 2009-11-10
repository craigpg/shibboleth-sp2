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
 * resolvertest.cpp
 * 
 * Tool to exercise SP attribute subsystems.
 */

#if defined (_MSC_VER) || defined(__BORLANDC__)
# include "config_win32.h"
#else
# include "config.h"
#endif

#ifdef WIN32
# define _CRT_NONSTDC_NO_DEPRECATE 1
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include <shibsp/Application.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/attribute/Attribute.h>
#include <shibsp/attribute/resolver/ResolutionContext.h>
#include <shibsp/handler/AssertionConsumerService.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>
#include <shibsp/util/SPConstants.h>

#include <saml/exceptions.h>
#include <saml/saml1/core/Assertions.h>
#include <saml/saml2/core/Assertions.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <xercesc/util/XMLUniDefs.hpp>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/util/ParserPool.h>
#include <xmltooling/util/XMLHelper.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace xercesc;
using namespace std;

#if defined (_MSC_VER)
    #pragma warning( push )
    #pragma warning( disable : 4250 )
#endif

class ResolverTest : public shibsp::AssertionConsumerService
{
public:
    ResolverTest(const DOMElement* e, const char* appId)
        : shibsp::AssertionConsumerService(e, appId, Category::getInstance(SHIBSP_LOGCAT".Utilities.ResolverTest")) {
    }
    virtual ~ResolverTest() {}
    
    ResolutionContext* resolveAttributes (
        const Application& application,
        const RoleDescriptor* issuer,
        const XMLCh* protocol,
        const saml1::NameIdentifier* v1nameid,
        const saml2::NameID* nameid,
        const XMLCh* authncontext_class,
        const XMLCh* authncontext_decl,
        const vector<const Assertion*>* tokens
        ) const {
        return shibsp::AssertionConsumerService::resolveAttributes(
            application, issuer, protocol, v1nameid, nameid, authncontext_class, authncontext_decl, tokens
            );
    }

private:
    void implementProtocol(
        const Application& application,
        const HTTPRequest& httpRequest,
        HTTPResponse& httpResponse,
        SecurityPolicy& policy,
        const PropertySet* settings,
        const XMLObject& xmlObject
        ) const {
            throw FatalProfileException("Should never be called.");
    }
};

#if defined (_MSC_VER)
    #pragma warning( pop )
#endif

void usage()
{
    cerr << "usage: resolvertest -n <name> -i <IdP> -p <protocol> [-f <format URI> -a <application id>]" << endl;
    cerr << "       resolvertest [-a <application id>] < assertion.xml" << endl;
}

int main(int argc,char* argv[])
{
    char* a_param=NULL;
    char* n_param=NULL;
    char* f_param=NULL;
    char* i_param=NULL;
    char* prot = NULL;
    const XMLCh* protocol = NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-n") && i+1<argc)
            n_param=argv[++i];
        else if (!strcmp(argv[i],"-f") && i+1<argc)
            f_param=argv[++i];
        else if (!strcmp(argv[i],"-i") && i+1<argc)
            i_param=argv[++i];
        else if (!strcmp(argv[i],"-p") && i+1<argc)
            prot=argv[++i];
        else if (!strcmp(argv[i],"-saml10"))
            protocol=samlconstants::SAML10_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml11"))
            protocol=samlconstants::SAML11_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml2"))
            protocol=samlconstants::SAML20P_NS;
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            a_param=argv[++i];
    }

    if (n_param && !i_param) {
        usage();
        return -10;
    }

    if (!a_param)
        a_param="default";

    if (n_param) {
        if (!protocol) {
            if (prot)
                protocol = XMLString::transcode(prot);
        }
        if (!protocol) {
            usage();
            return -10;
        }
    }

    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(
        SPConfig::Metadata |
        SPConfig::Trust |
        SPConfig::AttributeResolution |
        SPConfig::Credentials |
        SPConfig::OutOfProcess |
        SPConfig::Caching
        );
    if (!conf.init())
        return -1;
    if (!conf.instantiate()) {
        conf.term();
        return -2;
    }

    ServiceProvider* sp=conf.getServiceProvider();
    sp->lock();

    Category& log = Category::getInstance(SHIBSP_LOGCAT".Utility.ResolverTest");

    const Application* app = sp->getApplication(a_param);
    if (!app) {
        log.error("unknown application ID (%s)", a_param);
        sp->unlock();
        conf.term();
        return -3;
    }

    try {
        ResolutionContext* ctx;

        if (n_param) {
            auto_ptr_XMLCh issuer(i_param);
            auto_ptr_XMLCh name(n_param);
            auto_ptr_XMLCh format(f_param);

            MetadataProvider* m=app->getMetadataProvider();
            xmltooling::Locker mlocker(m);
            MetadataProviderCriteria mc(*app, i_param, &IDPSSODescriptor::ELEMENT_QNAME, protocol);
            pair<const EntityDescriptor*,const RoleDescriptor*> site=m->getEntityDescriptor(mc);
            if (!site.first)
                throw MetadataException("Unable to locate metadata for IdP ($1).", params(1,i_param));

            // Build NameID(s).
            auto_ptr<saml2::NameID> v2name(saml2::NameIDBuilder::buildNameID());
            v2name->setName(name.get());
            v2name->setFormat(format.get());
            saml1::NameIdentifier* v1name = NULL;
            if (!XMLString::equals(protocol, samlconstants::SAML20P_NS)) {
                v1name = saml1::NameIdentifierBuilder::buildNameIdentifier();
                v1name->setName(name.get());
                v1name->setFormat(format.get());
                v1name->setNameQualifier(issuer.get());
            }

            ResolverTest rt(NULL, a_param);
            try {
                ctx = rt.resolveAttributes(*app, site.second, protocol, v1name, v2name.get(), NULL, NULL, NULL);
            }
            catch (...) {
                delete v1name;
                throw;
            }
        }
        else {
            // Try and load assertion from stdin.
            DOMDocument* doc = XMLToolingConfig::getConfig().getParser().parse(cin);
            XercesJanitor<DOMDocument> docjan(doc);
            auto_ptr<XMLObject> token(XMLObjectBuilder::buildOneFromElement(doc->getDocumentElement(), true));
            docjan.release();

            // Get the issuer and protocol and NameIDs.
            const XMLCh* issuer = NULL;
            const saml1::NameIdentifier* v1name = NULL;
            saml2::NameID* v2name = NULL;
            saml2::Assertion* a2 = dynamic_cast<saml2::Assertion*>(token.get());
            saml1::Assertion* a1 = dynamic_cast<saml1::Assertion*>(token.get());
            if (a2) {
                const saml2::Issuer* iss = a2->getIssuer();
                issuer = iss ? iss->getName() : NULL;
                protocol = samlconstants::SAML20P_NS;
                v2name = a2->getSubject() ? a2->getSubject()->getNameID() : NULL;
            }
            else if (a1) {
                issuer = a1->getIssuer();
                if (a1->getMinorVersion().first && a1->getMinorVersion().second == 0)
                    protocol = samlconstants::SAML10_PROTOCOL_ENUM;
                else
                    protocol = samlconstants::SAML11_PROTOCOL_ENUM;
                v1name = a1->getAuthenticationStatements().size() ?
                    a1->getAuthenticationStatements().front()->getSubject()->getNameIdentifier() : NULL;
                if (!v1name)
                    v1name = a1->getAttributeStatements().size() ?
                    a1->getAttributeStatements().front()->getSubject()->getNameIdentifier() : NULL;
                if (v1name) {
                    // Normalize the SAML 1.x NameIdentifier...
                    v2name = saml2::NameIDBuilder::buildNameID();
                    v2name->setName(v1name->getName());
                    v2name->setFormat(v1name->getFormat());
                    v2name->setNameQualifier(v1name->getNameQualifier());
                }
            }
            else {
                throw FatalProfileException("Unknown assertion type.");
            }

            auto_ptr<saml2::NameID> nameidwrapper(v1name ? v2name : NULL);

            if (!issuer)
                throw FatalProfileException("Unable to determine issuer.");

            MetadataProvider* m=app->getMetadataProvider();
            xmltooling::Locker mlocker(m);
            MetadataProviderCriteria mc(*app, issuer, &IDPSSODescriptor::ELEMENT_QNAME, protocol);
            pair<const EntityDescriptor*,const RoleDescriptor*> site=m->getEntityDescriptor(mc);
            if (!site.first) {
                auto_ptr_char temp(issuer);
                throw MetadataException("Unable to locate metadata for IdP ($1).", params(1,temp.get()));
            }
            
            vector<const Assertion*> tokens(1, dynamic_cast<Assertion*>(token.get()));
            ResolverTest rt(NULL, a_param);
            ctx = rt.resolveAttributes(*app, site.second, protocol, v1name, v2name, NULL, NULL, &tokens);
        }

        auto_ptr<ResolutionContext> wrapper(ctx);
        for (vector<Attribute*>::const_iterator a = ctx->getResolvedAttributes().begin(); a != ctx->getResolvedAttributes().end(); ++a) {
            for (vector<string>::const_iterator s = (*a)->getAliases().begin(); s != (*a)->getAliases().end(); ++s) {
                cout << *s << ": ";
                for (vector<string>::const_iterator v = (*a)->getSerializedValues().begin(); v != (*a)->getSerializedValues().end(); ++v) {
                    if (v != (*a)->getSerializedValues().begin())
                        cout << ';';
                    cout << *v;
                }
                cout << endl;
            }
        }
        cout << endl;
    }
    catch(exception& ex) {
        log.error(ex.what());
        sp->unlock();
        conf.term();
        return -10;
    }

    sp->unlock();
    conf.term();
    return 0;
}
