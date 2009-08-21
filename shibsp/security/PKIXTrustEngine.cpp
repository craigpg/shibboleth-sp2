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
 * PKIXTrustEngine.cpp
 * 
 * Shibboleth-specific PKIX-validation TrustEngine
 */

#include "internal.h"
#include "metadata/MetadataExt.h"
#include "security/PKIXTrustEngine.h"

#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/saml2/metadata/ObservableMetadataProvider.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/AbstractPKIXTrustEngine.h>
#include <xmltooling/security/KeyInfoResolver.h>
#include <xmltooling/security/X509Credential.h>

using namespace shibsp;
using namespace opensaml::saml2md;
using namespace xmlsignature;
using namespace xmltooling;
using namespace std;

namespace shibsp {

    class SHIBSP_DLLLOCAL PKIXTrustEngine : public AbstractPKIXTrustEngine, public ObservableMetadataProvider::Observer
    {
    public:
        PKIXTrustEngine(const DOMElement* e=NULL) : AbstractPKIXTrustEngine(e), m_credLock(RWLock::create()) {
        }
        virtual ~PKIXTrustEngine() {
            for (map<const ObservableMetadataProvider*,credmap_t>::iterator i=m_credentialMap.begin(); i!=m_credentialMap.end(); ++i) {
                i->first->removeObserver(this);
                for (credmap_t::iterator creds = i->second.begin(); creds!=i->second.end(); ++creds)
                    for_each(creds->second.begin(), creds->second.end(), xmltooling::cleanup<X509Credential>());
            }
            delete m_credLock;
        }
        
        AbstractPKIXTrustEngine::PKIXValidationInfoIterator* getPKIXValidationInfoIterator(
            const CredentialResolver& pkixSource, CredentialCriteria* criteria=NULL
            ) const;

        void onEvent(const ObservableMetadataProvider& metadata) const {
            // Destroy credentials we cached from this provider.
            m_credLock->wrlock();
            credmap_t& cmap = m_credentialMap[&metadata];
            for (credmap_t::iterator creds = cmap.begin(); creds!=cmap.end(); ++creds)
                for_each(creds->second.begin(), creds->second.end(), xmltooling::cleanup<X509Credential>());
            cmap.clear();
            m_credLock->unlock();
        }

        const KeyInfoResolver* getKeyInfoResolver() const {
            return m_keyInfoResolver ? m_keyInfoResolver : XMLToolingConfig::getConfig().getKeyInfoResolver();
        }

    private:
        friend class SHIBSP_DLLLOCAL MetadataPKIXIterator;
        mutable RWLock* m_credLock;
        typedef map< const KeyAuthority*,vector<X509Credential*> > credmap_t;
        mutable map<const ObservableMetadataProvider*,credmap_t> m_credentialMap;
    };
    
    SHIBSP_DLLLOCAL PluginManager<TrustEngine,string,const DOMElement*>::Factory PKIXTrustEngineFactory;

    TrustEngine* SHIBSP_DLLLOCAL PKIXTrustEngineFactory(const DOMElement* const & e)
    {
        return new PKIXTrustEngine(e);
    }

    class SHIBSP_DLLLOCAL MetadataPKIXIterator : public AbstractPKIXTrustEngine::PKIXValidationInfoIterator
    {
    public:
        MetadataPKIXIterator(const PKIXTrustEngine& engine, const MetadataProvider& pkixSource, MetadataCredentialCriteria& criteria);

        virtual ~MetadataPKIXIterator() {
            if (m_caching)
                m_engine.m_credLock->unlock();
            for_each(m_ownedCreds.begin(), m_ownedCreds.end(), xmltooling::cleanup<Credential>());
        }

        bool next();

        int getVerificationDepth() const {
            pair<bool,int> vd = m_current->getVerifyDepth();
            return vd.first ? vd.second : 1;
        }
        
        const vector<XSECCryptoX509*>& getTrustAnchors() const {
            return m_certs;
        }

        const vector<XSECCryptoX509CRL*>& getCRLs() const {
            return m_crls;
        }
    
    private:
        void populate();
        bool m_caching;
        const PKIXTrustEngine& m_engine;
        map<const ObservableMetadataProvider*,PKIXTrustEngine::credmap_t>::iterator m_credCache;
        const XMLObject* m_obj;
        const Extensions* m_extBlock;
        const KeyAuthority* m_current;
        vector<XMLObject*>::const_iterator m_iter;
        vector<XSECCryptoX509*> m_certs;
        vector<XSECCryptoX509CRL*> m_crls;
        vector<X509Credential*> m_ownedCreds;
    };
};

void shibsp::registerPKIXTrustEngine()
{
    XMLToolingConfig::getConfig().TrustEngineManager.registerFactory(SHIBBOLETH_PKIX_TRUSTENGINE, PKIXTrustEngineFactory);
}

AbstractPKIXTrustEngine::PKIXValidationInfoIterator* PKIXTrustEngine::getPKIXValidationInfoIterator(
    const CredentialResolver& pkixSource, CredentialCriteria* criteria
    ) const
{
    // Make sure these are metadata objects.
    const MetadataProvider& metadata = dynamic_cast<const MetadataProvider&>(pkixSource);
    MetadataCredentialCriteria* metacrit = dynamic_cast<MetadataCredentialCriteria*>(criteria);
    if (!metacrit)
        throw MetadataException("Cannot obtain PKIX information without a MetadataCredentialCriteria object.");

    return new MetadataPKIXIterator(*this, metadata,*metacrit);
}

MetadataPKIXIterator::MetadataPKIXIterator(
    const PKIXTrustEngine& engine, const MetadataProvider& pkixSource, MetadataCredentialCriteria& criteria
    ) : m_caching(false), m_engine(engine), m_obj(criteria.getRole().getParent()), m_extBlock(NULL), m_current(NULL)
{
    // If we can't hook the metadata for changes, then we can't do any caching and the rest of this is academic.
    const ObservableMetadataProvider* observable = dynamic_cast<const ObservableMetadataProvider*>(&pkixSource);
    if (!observable)
        return;

    // While holding read lock, see if this metadata plugin has been seen before.
    m_engine.m_credLock->rdlock();
    m_credCache = m_engine.m_credentialMap.find(observable);
    if (m_credCache==m_engine.m_credentialMap.end()) {

        // We need to elevate the lock and retry.
        m_engine.m_credLock->unlock();
        m_engine.m_credLock->wrlock();
        m_credCache = m_engine.m_credentialMap.find(observable);
        if (m_credCache==m_engine.m_credentialMap.end()) {

            // It's still brand new, so hook it for cache activation.
            observable->addObserver(&m_engine);

            // Prime the map reference with an empty credential map.
            m_credCache = m_engine.m_credentialMap.insert(make_pair(observable,PKIXTrustEngine::credmap_t())).first;
            
            // Downgrade the lock.
            // We don't have to recheck because we never erase the master map entry entirely, even on changes.
            m_engine.m_credLock->unlock();
            m_engine.m_credLock->rdlock();
        }
    }
    
    // We've hooked the metadata for changes, and we know we can cache against it.
    m_caching = true;
}


bool MetadataPKIXIterator::next()
{
    // If we had an active block, look for another in the same block.
    if (m_extBlock) {
        // Keep going until we hit the end of the block.
        vector<XMLObject*>::const_iterator end = m_extBlock->getUnknownXMLObjects().end();
        while (m_iter != end) {
            // If we hit a KeyAuthority, remember it and signal.
            if (m_current=dynamic_cast<KeyAuthority*>(*m_iter++)) {
                populate();
                return true;
            }
        }
        
        // If we get here, we hit the end of this Extensions block.
        // Climb a level, if possible.
        m_obj = m_obj->getParent();
        m_current = NULL;
        m_extBlock = NULL;
    }

    // If we get here, we try and find an Extensions block.
    while (m_obj) {
        const EntityDescriptor* entity = dynamic_cast<const EntityDescriptor*>(m_obj);
        if (entity) {
            m_extBlock = entity->getExtensions();
        }
        else {
            const EntitiesDescriptor* entities = dynamic_cast<const EntitiesDescriptor*>(m_obj);
            if (entities) {
                m_extBlock = entities->getExtensions();
            }
        }
        
        if (m_extBlock) {
            m_iter = m_extBlock->getUnknownXMLObjects().begin();
            return next();
        }
        
        // Jump a level and try again.
        m_obj = m_obj->getParent();
    }

    return false;
}

void MetadataPKIXIterator::populate()
{
    // Dump anything old.
    m_certs.clear();
    m_crls.clear();
    for_each(m_ownedCreds.begin(), m_ownedCreds.end(), xmltooling::cleanup<Credential>());

    if (m_caching) {
        // We're holding a read lock. Search for "resolved" creds.
        PKIXTrustEngine::credmap_t::iterator cached = m_credCache->second.find(m_current);
        if (cached!=m_credCache->second.end()) {
            // Copy over the information.
            for (vector<X509Credential*>::const_iterator c=cached->second.begin(); c!=cached->second.end(); ++c) {
                m_certs.insert(m_certs.end(), (*c)->getEntityCertificateChain().begin(), (*c)->getEntityCertificateChain().end());
                if ((*c)->getCRL())
                    m_crls.push_back((*c)->getCRL());
            }
            return;
        }
    }

    // We're either not caching or didn't find the results we need, so we have to resolve them.
    const vector<KeyInfo*>& keyInfos = m_current->getKeyInfos();
    for (vector<KeyInfo*>::const_iterator k = keyInfos.begin(); k!=keyInfos.end(); ++k) {
        auto_ptr<Credential> cred (m_engine.getKeyInfoResolver()->resolve(*k, X509Credential::RESOLVE_CERTS | X509Credential::RESOLVE_CRLS));
        X509Credential* xcred = dynamic_cast<X509Credential*>(cred.get());
        if (xcred) {
            m_ownedCreds.push_back(xcred);
            cred.release();
        }
    }

    // Copy over the new information.
    for (vector<X509Credential*>::const_iterator c=m_ownedCreds.begin(); c!=m_ownedCreds.end(); ++c) {
        m_certs.insert(m_certs.end(), (*c)->getEntityCertificateChain().begin(), (*c)->getEntityCertificateChain().end());
        if ((*c)->getCRL())
            m_crls.push_back((*c)->getCRL());
    }

    // As a last step, if we're caching, try and elevate to a write lock for cache insertion.
    if (m_caching) {
        m_engine.m_credLock->unlock();
        m_engine.m_credLock->wrlock();
        if (m_credCache->second.count(m_current)==0) {
            // Transfer objects into cache.
            m_credCache->second[m_current] = m_ownedCreds;
            m_ownedCreds.clear();
        }
        m_engine.m_credLock->unlock();
        m_engine.m_credLock->rdlock();

        // In theory we could have lost the objects but that shouldn't be possible
        // since the metadata itself is locked and shouldn't change behind us.
    }
}
