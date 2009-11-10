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
 * ArtifactResolver.cpp
 * 
 * SAML artifact resolver for SP use.
 */

#include "internal.h"
#include "Application.h"
#include "binding/ArtifactResolver.h"
#include "binding/SOAPClient.h"
#include "security/SecurityPolicy.h"

#include <saml/exceptions.h>
#include <saml/saml1/core/Protocols.h>
#include <saml/saml1/binding/SAML1SOAPClient.h>
#include <saml/saml2/core/Protocols.h>
#include <saml/saml2/binding/SAML2Artifact.h>
#include <saml/saml2/binding/SAML2SOAPClient.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/util/SAMLConstants.h>

using namespace shibsp;
using namespace opensaml::saml1p;
using namespace opensaml::saml2;
using namespace opensaml::saml2p;
using namespace opensaml::saml2md;
using namespace opensaml;
using namespace xmltooling;
using namespace std;

ArtifactResolver::ArtifactResolver()
{
}

ArtifactResolver::~ArtifactResolver()
{
}

saml1p::Response* ArtifactResolver::resolve(
    const vector<SAMLArtifact*>& artifacts,
    const IDPSSODescriptor& idpDescriptor,
    opensaml::SecurityPolicy& policy
    ) const
{
    MetadataCredentialCriteria mcc(idpDescriptor);
    shibsp::SecurityPolicy& sppolicy = dynamic_cast<shibsp::SecurityPolicy&>(policy);
    shibsp::SOAPClient soaper(sppolicy);

    bool foundEndpoint = false;
    auto_ptr_XMLCh binding(samlconstants::SAML1_BINDING_SOAP);
    saml1p::Response* response=NULL;
    const vector<ArtifactResolutionService*>& endpoints=idpDescriptor.getArtifactResolutionServices();
    for (vector<ArtifactResolutionService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            foundEndpoint = true;
            auto_ptr_char loc((*ep)->getLocation());
            saml1p::Request* request = saml1p::RequestBuilder::buildRequest();
            request->setMinorVersion(idpDescriptor.hasSupport(samlconstants::SAML11_PROTOCOL_ENUM) ? 1 : 0);
            for (vector<SAMLArtifact*>::const_iterator a = artifacts.begin(); a!=artifacts.end(); ++a) {
                auto_ptr_XMLCh artbuf((*a)->encode().c_str());
                AssertionArtifact* aa = AssertionArtifactBuilder::buildAssertionArtifact();
                aa->setArtifact(artbuf.get());
                request->getAssertionArtifacts().push_back(aa);
            }

            SAML1SOAPClient client(soaper, false);
            client.sendSAML(request, sppolicy.getApplication().getId(), mcc, loc.get());
            response = client.receiveSAML();
        }
        catch (exception& ex) {
            Category::getInstance(SHIBSP_LOGCAT".ArtifactResolver").error("exception resolving SAML 1.x artifact(s): %s", ex.what());
            soaper.reset();
        }
    }

    if (!foundEndpoint)
        throw MetadataException("No compatible endpoint found in issuer's metadata.");
    else if (!response)
        throw BindingException("Unable to resolve artifact(s) into a SAML response.");
    const xmltooling::QName* code = (response->getStatus() && response->getStatus()->getStatusCode()) ? response->getStatus()->getStatusCode()->getValue() : NULL;
    if (!code || *code != saml1p::StatusCode::SUCCESS) {
        delete response;
        throw BindingException("Identity provider returned a SAML error in response to artifact(s).");
    }

    // The SOAP client handles policy evaluation against the SOAP and Response layer,
    // but no security checking is done here.
    return response;
}

ArtifactResponse* ArtifactResolver::resolve(
    const SAML2Artifact& artifact,
    const SSODescriptorType& ssoDescriptor,
    opensaml::SecurityPolicy& policy
    ) const
{
    MetadataCredentialCriteria mcc(ssoDescriptor);
    shibsp::SecurityPolicy& sppolicy = dynamic_cast<shibsp::SecurityPolicy&>(policy);
    shibsp::SOAPClient soaper(sppolicy);

    bool foundEndpoint = false;
    auto_ptr_XMLCh binding(samlconstants::SAML20_BINDING_SOAP);
    ArtifactResponse* response=NULL;
    const vector<ArtifactResolutionService*>& endpoints=ssoDescriptor.getArtifactResolutionServices();
    for (vector<ArtifactResolutionService*>::const_iterator ep=endpoints.begin(); !response && ep!=endpoints.end(); ++ep) {
        try {
            if (!XMLString::equals((*ep)->getBinding(),binding.get()))
                continue;
            foundEndpoint = true;
            auto_ptr_char loc((*ep)->getLocation());
            ArtifactResolve* request = ArtifactResolveBuilder::buildArtifactResolve();
            Issuer* iss = IssuerBuilder::buildIssuer();
            request->setIssuer(iss);
            iss->setName(sppolicy.getApplication().getRelyingParty(dynamic_cast<EntityDescriptor*>(ssoDescriptor.getParent()))->getXMLString("entityID").second);
            auto_ptr_XMLCh artbuf(artifact.encode().c_str());
            Artifact* a = ArtifactBuilder::buildArtifact();
            a->setArtifact(artbuf.get());
            request->setArtifact(a);

            SAML2SOAPClient client(soaper, false);
            client.sendSAML(request, sppolicy.getApplication().getId(), mcc, loc.get());
            StatusResponseType* srt = client.receiveSAML();
            if (!(response = dynamic_cast<ArtifactResponse*>(srt))) {
                delete srt;
                break;
            }
        }
        catch (exception& ex) {
            Category::getInstance(SHIBSP_LOGCAT".ArtifactResolver").error("exception resolving SAML 2.0 artifact: %s", ex.what());
            soaper.reset();
        }
    }

    if (!foundEndpoint)
        throw MetadataException("No compatible endpoint found in issuer's metadata.");
    else if (!response)
        throw BindingException("Unable to resolve artifact(s) into a SAML response.");
    else if (!response->getStatus() || !response->getStatus()->getStatusCode() ||
           !XMLString::equals(response->getStatus()->getStatusCode()->getValue(), saml2p::StatusCode::SUCCESS)) {
        auto_ptr<ArtifactResponse> wrapper(response);
        BindingException ex("Identity provider returned a SAML error in response to artifact.");
        annotateException(&ex, &ssoDescriptor, response->getStatus());  // rethrow
    }

    // The SOAP client handles policy evaluation against the SOAP and Response layer,
    // but no security checking is done here.
    return response;
}
