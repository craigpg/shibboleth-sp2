#! /bin/sh

while getopts a:c:e:h:n:o:s:t: c
     do
         case $c in
           c)         CERTS[${#CERTS[*]}]=$OPTARG;;
           e)         ENTITYID=$OPTARG;;
           h)         HOSTS[${#HOSTS[*]}]=$OPTARG;;
           n)         NAKEDHOSTS[${#NAKEDHOSTS[*]}]=$OPTARG;;
           o)         ORGNAME=$OPTARG;;
           a)         ADMIN[${#ADMIN[*]}]=$OPTARG;;
           s)         SUP[${#SUP[*]}]=$OPTARG;;
           t)         TECH[${#TECH[*]}]=$OPTARG;;
           \?)        echo metagen -c cert1 [-c cert2 ...] -h host1 [-h host2 ...] [-e entityID]
                      exit 1;;
         esac
     done

if [ ${#HOSTS[*]} -eq 0 -a ${#NAKEDHOSTS[*]} -eq 0 ] ; then
    echo metagen -c cert1 [-c cert2 ...] -h host1 [-h host2 ...] [-e entityID]
    exit 1
fi

if [ ${#CERTS[*]} -eq 0 ] ; then
    CERTS[${#CERTS[*]}]=sp-cert.pem
fi

for c in ${CERTS[@]}
do
    if  [ ! -s $c ] ; then
        echo Certificate file $c does not exist! 
        exit 2
    fi
done

if [ -z $ENTITYID ] ; then
    ENTITYID=https://${HOSTS[0]}/shibboleth
fi

cat <<EOF
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${ENTITYID}">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:1.0:protocol">
    <md:Extensions>
EOF

count=1
for h in ${HOSTS[@]}
do
  cat << EOF
      <DiscoveryResponse xmlns="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Binding="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Location="https://$h/Shibboleth.sso/DS" index="$count"/>
EOF
  let "count++"
done

for h in ${NAKEDHOSTS[@]}
do
  cat << EOF
      <DiscoveryResponse xmlns="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Binding="urn:oasis:names:tc:SAML:profiles:SSO:idp-discovery-protocol" Location="http://$h/Shibboleth.sso/DS" index="$count"/>
EOF
  let "count++"
done

cat << EOF
    </md:Extensions>
EOF

for c in ${CERTS[@]}
do
cat << EOF
    <md:KeyDescriptor>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
EOF
grep -v ^- $c
cat << EOF
          </ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
EOF
done

cat << EOF
    <!--
EOF

for h in ${HOSTS[@]}
do
  cat <<EOF
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://$h/Shibboleth.sso/SLO/SOAP"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://$h/Shibboleth.sso/SLO/Redirect"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://$h/Shibboleth.sso/SLO/POST"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://$h/Shibboleth.sso/SLO/Artifact"/>
EOF
done

for h in ${NAKEDHOSTS[@]}
do
  cat <<EOF
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://$h/Shibboleth.sso/SLO/SOAP"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://$h/Shibboleth.sso/SLO/Redirect"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://$h/Shibboleth.sso/SLO/POST"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://$h/Shibboleth.sso/SLO/Artifact"/>
EOF
done

for h in ${HOSTS[@]}
do
  cat <<EOF
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://$h/Shibboleth.sso/NIM/SOAP"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://$h/Shibboleth.sso/NIM/Redirect"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://$h/Shibboleth.sso/NIM/POST"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://$h/Shibboleth.sso/NIM/Artifact"/>
EOF
done

for h in ${NAKEDHOSTS[@]}
do
  cat <<EOF
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="http://$h/Shibboleth.sso/NIM/SOAP"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="http://$h/Shibboleth.sso/NIM/Redirect"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://$h/Shibboleth.sso/NIM/POST"/>
    <md:ManageNameIDService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://$h/Shibboleth.sso/NIM/Artifact"/>
EOF
done

cat <<EOF
    -->
EOF

count=0
for h in ${HOSTS[@]}
do
  cat <<EOF
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://$h/Shibboleth.sso/SAML2/POST" index="$((count+1))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://$h/Shibboleth.sso/SAML2/POST-SimpleSign" index="$((count+2))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://$h/Shibboleth.sso/SAML2/Artifact" index="$((count+3))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="https://$h/Shibboleth.sso/SAML2/ECP" index="$((count+4))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="https://$h/Shibboleth.sso/SAML/POST" index="$((count+5))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:artifact-01" Location="https://$h/Shibboleth.sso/SAML/Artifact" index="$((count+6))"/>
EOF
  let "count+=6"
done

for h in ${NAKEDHOSTS[@]}
do
  cat <<EOF
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://$h/Shibboleth.sso/SAML2/POST" index="$((count+1))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="http://$h/Shibboleth.sso/SAML2/POST-SimpleSign" index="$((count+2))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="http://$h/Shibboleth.sso/SAML2/Artifact" index="$((count+3))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:PAOS" Location="http://$h/Shibboleth.sso/SAML2/ECP" index="$((count+4))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:browser-post" Location="http://$h/Shibboleth.sso/SAML/POST" index="$((count+5))"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:1.0:profiles:artifact-01" Location="http://$h/Shibboleth.sso/SAML/Artifact" index="$((count+6))"/>
EOF
  let "count+=6"
done

cat <<EOF 
  </md:SPSSODescriptor>
EOF

if [ -n "$ORGNAME" ] ; then
  cat <<EOF
  <md:Organization>
    <md:OrganizationName xml:lang="en">$ORGNAME</md:OrganizationName>
    <md:OrganizationDisplayName xml:lang="en">$ORGNAME</md:OrganizationDisplayName>
    <md:OrganizationURL xml:lang="en">$ENTITYID</md:OrganizationURL>
  </md:Organization>
EOF
fi

for c in ${ADMIN[@]}
do
  c=(${c//\// })
  cat <<EOF
  <md:ContactPerson contactType="administrative">
    <md:GivenName>${c[0]}</md:GivenName>
    <md:SurName>${c[1]}</md:SurName>
    <md:EmailAddress>${c[2]}</md:EmailAddress>
  </md:ContactPerson>
EOF
done

for c in ${SUP[@]}
do
  c=(${c//\// })
  cat <<EOF
  <md:ContactPerson contactType="support">
    <md:GivenName>${c[0]}</md:GivenName>
    <md:SurName>${c[1]}</md:SurName>
    <md:EmailAddress>${c[2]}</md:EmailAddress>
  </md:ContactPerson>
EOF
done

for c in ${TECH[@]}
do
  c=(${c//\// })
  cat <<EOF
  <md:ContactPerson contactType="technical">
    <md:GivenName>${c[0]}</md:GivenName>
    <md:SurName>${c[1]}</md:SurName>
    <md:EmailAddress>${c[2]}</md:EmailAddress>
  </md:ContactPerson>
EOF
done

cat <<EOF 
</md:EntityDescriptor>
EOF
