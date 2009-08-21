AUTOMAKE_OPTIONS = foreign

lib_LTLIBRARIES = libshibsp.la libshibsp-lite.la

libshibspincludedir = $(includedir)/shibsp

attrincludedir = $(includedir)/shibsp/attribute

attrresincludedir = $(includedir)/shibsp/attribute/resolver

attrfiltincludedir = $(includedir)/shibsp/attribute/filtering

bindincludedir = $(includedir)/shibsp/binding

handincludedir = $(includedir)/shibsp/handler

liteincludedir = $(includedir)/shibsp/lite

mdincludedir = $(includedir)/shibsp/metadata

remincludedir = $(includedir)/shibsp/remoting

secincludedir = $(includedir)/shibsp/security

utilincludedir = $(includedir)/shibsp/util

libshibspinclude_HEADERS = \
	AbstractSPRequest.h \
	AccessControl.h \
	Application.h \
	base.h \
	exceptions.h \
	paths.h \
	RequestMapper.h \
	ServiceProvider.h \
	SessionCache.h \
	SessionCacheEx.h \
	SPConfig.h \
	SPRequest.h \
	TransactionLog.h \
	version.h

attrinclude_HEADERS = \
	attribute/Attribute.h \
	attribute/AttributeDecoder.h \
	attribute/ExtensibleAttribute.h \
	attribute/NameIDAttribute.h \
	attribute/ScopedAttribute.h \
	attribute/SimpleAttribute.h \
	attribute/XMLAttribute.h

attrfiltinclude_HEADERS = \
	attribute/filtering/AttributeFilter.h \
	attribute/filtering/BasicFilteringContext.h \
	attribute/filtering/FilteringContext.h \
	attribute/filtering/FilterPolicyContext.h \
	attribute/filtering/MatchFunctor.h

attrresinclude_HEADERS = \
	attribute/resolver/AttributeExtractor.h \
	attribute/resolver/AttributeResolver.h \
	attribute/resolver/ResolutionContext.h

bindinclude_HEADERS = \
	binding/ArtifactResolver.h \
	binding/SOAPClient.h

handinclude_HEADERS = \
	handler/AbstractHandler.h \
	handler/AssertionConsumerService.h \
	handler/Handler.h \
	handler/LogoutHandler.h \
	handler/RemotedHandler.h \
	handler/SessionInitiator.h

liteinclude_HEADERS = \
	lite/CommonDomainCookie.h \
	lite/SAMLConstants.h

mdinclude_HEADERS = \
	metadata/MetadataExt.h \
	metadata/MetadataProviderCriteria.h

reminclude_HEADERS = \
	remoting/ddf.h \
	remoting/ListenerService.h
	
secinclude_HEADERS = \
	security/PKIXTrustEngine.h \
	security/SecurityPolicy.h

utilinclude_HEADERS = \
	util/CGIParser.h \
	util/DOMPropertySet.h \
	util/PropertySet.h \
	util/SPConstants.h \
	util/TemplateParameters.h

noinst_HEADERS = \
	internal.h \
	remoting/impl/SocketListener.h

common_sources = \
	AbstractSPRequest.cpp \
	Application.cpp \
	ServiceProvider.cpp \
	SPConfig.cpp \
	attribute/Attribute.cpp \
	attribute/ExtensibleAttribute.cpp \
	handler/impl/AbstractHandler.cpp \
	handler/impl/AssertionConsumerService.cpp \
	handler/impl/AssertionLookup.cpp \
	handler/impl/ChainingLogoutInitiator.cpp \
	handler/impl/ChainingSessionInitiator.cpp \
	handler/impl/CookieSessionInitiator.cpp \
	handler/impl/FormSessionInitiator.cpp \
	handler/impl/LocalLogoutInitiator.cpp \
	handler/impl/LogoutHandler.cpp \
	handler/impl/MetadataGenerator.cpp \
	handler/impl/RemotedHandler.cpp \
	handler/impl/StatusHandler.cpp \
	handler/impl/SessionHandler.cpp \
	handler/impl/SAML1Consumer.cpp \
	handler/impl/SAML2Consumer.cpp \
	handler/impl/SAML2ArtifactResolution.cpp \
	handler/impl/SAML2Logout.cpp \
	handler/impl/SAML2LogoutInitiator.cpp \
	handler/impl/SAML2NameIDMgmt.cpp \
	handler/impl/SAML2SessionInitiator.cpp \
	handler/impl/SAMLDSSessionInitiator.cpp \
	handler/impl/SessionInitiator.cpp \
	handler/impl/Shib1SessionInitiator.cpp \
	handler/impl/TransformSessionInitiator.cpp \
	handler/impl/WAYFSessionInitiator.cpp \
	impl/ChainingAccessControl.cpp \
    impl/StorageServiceSessionCache.cpp \
	impl/XMLAccessControl.cpp \
	impl/XMLRequestMapper.cpp \
	impl/XMLServiceProvider.cpp \
	remoting/impl/ddf.cpp \
	remoting/impl/ListenerService.cpp \
	remoting/impl/SocketListener.cpp \
	remoting/impl/TCPListener.cpp \
	remoting/impl/UnixListener.cpp \
	util/CGIParser.cpp \
	util/DOMPropertySet.cpp \
	util/SPConstants.cpp \
	util/TemplateParameters.cpp

libshibsp_lite_la_SOURCES = \
	${common_sources} \
	lite/CommonDomainCookie.cpp \
	lite/SAMLConstants.cpp

libshibsp_la_SOURCES = \
	${common_sources} \
	attribute/DOMAttributeDecoder.cpp \
	attribute/KeyInfoAttributeDecoder.cpp \
	attribute/NameIDAttributeDecoder.cpp \
	attribute/NameIDFromScopedAttributeDecoder.cpp \
	attribute/ScopedAttributeDecoder.cpp \
	attribute/StringAttributeDecoder.cpp \
	attribute/XMLAttributeDecoder.cpp \
	attribute/filtering/impl/AttributeFilter.cpp \
	attribute/filtering/impl/ChainingAttributeFilter.cpp \
	attribute/filtering/impl/XMLAttributeFilter.cpp \
	attribute/filtering/impl/MatchFunctor.cpp \
	attribute/filtering/impl/AndMatchFunctor.cpp \
	attribute/filtering/impl/AnyMatchFunctor.cpp \
	attribute/filtering/impl/NotMatchFunctor.cpp \
	attribute/filtering/impl/OrMatchFunctor.cpp \
	attribute/filtering/impl/AttributeIssuerStringFunctor.cpp \
	attribute/filtering/impl/AttributeRequesterStringFunctor.cpp \
	attribute/filtering/impl/AttributeScopeStringFunctor.cpp \
	attribute/filtering/impl/AttributeValueStringFunctor.cpp \
	attribute/filtering/impl/AuthenticationMethodStringFunctor.cpp \
	attribute/filtering/impl/AttributeIssuerRegexFunctor.cpp \
	attribute/filtering/impl/AttributeRequesterRegexFunctor.cpp \
	attribute/filtering/impl/AttributeScopeRegexFunctor.cpp \
	attribute/filtering/impl/AttributeValueRegexFunctor.cpp \
	attribute/filtering/impl/AuthenticationMethodRegexFunctor.cpp \
	attribute/filtering/impl/NumberOfAttributeValuesFunctor.cpp \
	attribute/filtering/impl/AttributeIssuerInEntityGroupFunctor.cpp \
	attribute/filtering/impl/AttributeRequesterInEntityGroupFunctor.cpp \
	attribute/filtering/impl/AttributeScopeMatchesShibMDScopeFunctor.cpp \
	attribute/resolver/impl/ChainingAttributeResolver.cpp \
	attribute/resolver/impl/QueryAttributeResolver.cpp \
	attribute/resolver/impl/SimpleAggregationAttributeResolver.cpp \
	attribute/resolver/impl/ChainingAttributeExtractor.cpp \
	attribute/resolver/impl/DelegationAttributeExtractor.cpp \
	attribute/resolver/impl/KeyDescriptorAttributeExtractor.cpp \
	attribute/resolver/impl/XMLAttributeExtractor.cpp \
	binding/impl/ArtifactResolver.cpp \
	binding/impl/SOAPClient.cpp \
	metadata/DynamicMetadataProvider.cpp \
	metadata/MetadataExtImpl.cpp \
	metadata/MetadataExtSchemaValidators.cpp \
	security/PKIXTrustEngine.cpp \
	security/SecurityPolicy.cpp

# this is different from the project version
# http://sources.redhat.com/autobook/autobook/autobook_91.html
libshibsp_la_LDFLAGS = $(XMLSEC_LIBS) -version-info 3:1:0
libshibsp_lite_la_LDFLAGS = $(LITE_LIBS) -version-info 3:1:0
libshibsp_lite_la_CPPFLAGS = -DSHIBSP_LITE

pkgsysconfdir = $(sysconfdir)/@PACKAGE@
pkgxmldir = $(datadir)/xml/@PACKAGE@
logdir = ${localstatedir}/log
rundir = $(localstatedir)/run
xmldir = $(datadir)/xml

paths.h: ${srcdir}/paths.h.in Makefile ${top_builddir}/config.status
	rm -f $@.tmp
	sed < ${srcdir}/$@.in > $@.tmp \
	    -e 's:@-PREFIX-@:${prefix}:g' \
        -e 's:@-LIBDIR-@:${libdir}:g' \
        -e 's:@-SYSCONFDIR-@:${sysconfdir}:g' \
        -e 's:@-LOGDIR-@:${logdir}:g' \
        -e 's:@-RUNDIR-@:${rundir}:g' \
        -e 's:@-XMLDIR-@:${xmldir}:g' \
	    -e 's:@-PKGSYSCONFDIR-@:${pkgsysconfdir}:g' \
	    -e 's:@-PKGXMLDIR-@:${pkgxmldir}:g' \
	    -e 's:@-XMLTOOLINGXMLDIR-@:${XMLTOOLINGXMLDIR}:g' \
	    -e 's:@-OPENSAMLXMLDIR-@:${OPENSAMLXMLDIR}:g'
	cmp -s $@ $@.tmp || mv $@.tmp $@
	rm -f $@.tmp

install-exec-hook:
	for la in $(lib_LTLIBRARIES) ; do rm -f $(DESTDIR)$(libdir)/$$la ; done

EXTRA_DIST = shibsp.vcproj shibsp-lite.vcproj paths.h.in resource.h shibsp.rc
BUILT_SOURCES = paths.h
