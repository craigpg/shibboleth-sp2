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
 * mdquery.cpp
 * 
 * SAML Metadata Query tool layered on SP configuration
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
#include <shibsp/exceptions.h>
#include <shibsp/SPConfig.h>
#include <shibsp/ServiceProvider.h>
#include <shibsp/metadata/MetadataProviderCriteria.h>
#include <shibsp/util/SPConstants.h>
#include <saml/saml2/metadata/Metadata.h>
#include <xmltooling/logging.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace std;

void usage()
{
    cerr << "usage: mdquery -e <entityID> [-a <app id> -nostrict]" << endl;
    cerr << "       mdquery -e <entityID> -r <role> -p <protocol> [-a <app id> -ns <namespace> -nostrict]" << endl;
}

int main(int argc,char* argv[])
{
    char* entityID = NULL;
    char* appID = "default";
    bool strict = true;
    char* prot = NULL;
    const XMLCh* protocol = NULL;
    char* rname = NULL;
    char* rns = NULL;

    for (int i=1; i<argc; i++) {
        if (!strcmp(argv[i],"-e") && i+1<argc)
            entityID=argv[++i];
        else if (!strcmp(argv[i],"-a") && i+1<argc)
            appID=argv[++i];
        else if (!strcmp(argv[i],"-p") && i+1<argc)
            prot=argv[++i];
        else if (!strcmp(argv[i],"-r") && i+1<argc)
            rname=argv[++i];
        else if (!strcmp(argv[i],"-ns") && i+1<argc)
            rns=argv[++i];
        else if (!strcmp(argv[i],"-saml10"))
            protocol=samlconstants::SAML10_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml11"))
            protocol=samlconstants::SAML11_PROTOCOL_ENUM;
        else if (!strcmp(argv[i],"-saml2"))
            protocol=samlconstants::SAML20P_NS;
        else if (!strcmp(argv[i],"-idp"))
            rname="IDPSSODescriptor";
        else if (!strcmp(argv[i],"-aa"))
            rname="AttributeAuthorityDescriptor";
        else if (!strcmp(argv[i],"-pdp"))
            rname="PDPDescriptor";
        else if (!strcmp(argv[i],"-sp"))
            rname="SPSSODescriptor";
        else if (!strcmp(argv[i],"-nostrict"))
            strict = false;
    }

    if (!entityID) {
        usage();
        exit(-10);
    }

    char* path=getenv("SHIBSP_SCHEMAS");
    if (!path)
        path=SHIBSP_SCHEMAS;
    char* config=getenv("SHIBSP_CONFIG");
    if (!config)
        config=SHIBSP_CONFIG;

    XMLToolingConfig::getConfig().log_config(getenv("SHIBSP_LOGGING") ? getenv("SHIBSP_LOGGING") : SHIBSP_LOGGING);

    SPConfig& conf=SPConfig::getConfig();
    conf.setFeatures(SPConfig::Metadata | SPConfig::Trust | SPConfig::OutOfProcess | SPConfig::Credentials);
    if (!conf.init(path))
        return -1;

    if (rname) {
        if (!protocol) {
            if (prot)
                protocol = XMLString::transcode(prot);
        }
        if (!protocol) {
            conf.term();
            usage();
            exit(-10);
        }
    }

    try {
        static const XMLCh _path[] = UNICODE_LITERAL_4(p,a,t,h);
        static const XMLCh validate[] = UNICODE_LITERAL_8(v,a,l,i,d,a,t,e);
        xercesc::DOMDocument* dummydoc=XMLToolingConfig::getConfig().getParser().newDocument();
        XercesJanitor<xercesc::DOMDocument> docjanitor(dummydoc);
        xercesc::DOMElement* dummy = dummydoc->createElementNS(NULL,_path);
        auto_ptr_XMLCh src(config);
        dummy->setAttributeNS(NULL,_path,src.get());
        dummy->setAttributeNS(NULL,validate,xmlconstants::XML_ONE);
        conf.setServiceProvider(conf.ServiceProviderManager.newPlugin(XML_SERVICE_PROVIDER,dummy));
        conf.getServiceProvider()->init();
    }
    catch (exception&) {
        conf.term();
        return -2;
    }

    ServiceProvider* sp=conf.getServiceProvider();
    sp->lock();

    Category& log = Category::getInstance(SHIBSP_LOGCAT".Utility.MDQuery");

    const Application* app = sp->getApplication(appID);
    if (!app) {
        log.error("unknown application ID (%s)", appID);
        sp->unlock();
        conf.term();
        return -3;
    }

    app->getMetadataProvider()->lock();
    MetadataProviderCriteria mc(*app, entityID, NULL, NULL, strict);
    if (rname) {
        const XMLCh* ns = rns ? XMLString::transcode(rns) : samlconstants::SAML20MD_NS;
        auto_ptr_XMLCh n(rname);
        QName q(ns, n.get());
        mc.role = &q;
        mc.protocol = protocol;
        const RoleDescriptor* role = app->getMetadataProvider()->getEntityDescriptor(mc).second;
        if (role)
            XMLHelper::serialize(role->marshall(), cout, true);
        else
            log.error("compatible role %s not found for (%s)", q.toString().c_str(), entityID);
    }
    else {
        const EntityDescriptor* entity = app->getMetadataProvider()->getEntityDescriptor(mc).first;
        if (entity)
            XMLHelper::serialize(entity->marshall(), cout, true);
        else
            log.error("no metadata found for (%s)", entityID);
    }

    app->getMetadataProvider()->unlock();

    sp->unlock();
    conf.term();
    return 0;
}
