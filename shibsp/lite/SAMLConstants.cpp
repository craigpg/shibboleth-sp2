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
 * SAMLConstants.cpp
 *
 * SAML XML namespace constants
 */


#include "internal.h"
#include "lite/SAMLConstants.h"
#include <xercesc/util/XMLUniDefs.hpp>

using namespace xercesc;
using namespace samlconstants;

const XMLCh samlconstants::PAOS_NS[] = // urn:liberty:paos:2003-08
{ chLatin_u, chLatin_r, chLatin_n, chColon,
  chLatin_l, chLatin_i, chLatin_b, chLatin_e, chLatin_r, chLatin_t, chLatin_y, chColon,
  chLatin_p, chLatin_a, chLatin_o, chLatin_s, chColon,
  chDigit_2, chDigit_0, chDigit_0, chDigit_3, chDash, chDigit_0, chDigit_8, chNull
};

const XMLCh samlconstants::PAOS_PREFIX[] = UNICODE_LITERAL_4(p,a,o,s);

const XMLCh samlconstants::SAML1_NS[] = // urn:oasis:names:tc:SAML:1.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh samlconstants::SAML1P_NS[] = // urn:oasis:names:tc:SAML:1.0:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh samlconstants::SAML1_PREFIX[] = UNICODE_LITERAL_4(s,a,m,l);

const XMLCh samlconstants::SAML1P_PREFIX[] = UNICODE_LITERAL_5(s,a,m,l,p);

const XMLCh samlconstants::SAML20_VERSION[] = // 2.0
{ chDigit_2, chPeriod, chDigit_0, chNull
};

const XMLCh samlconstants::SAML20_NS[] = // urn:oasis:names:tc:SAML:2.0:assertion
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_s, chLatin_s, chLatin_e, chLatin_r, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh samlconstants::SAML20P_NS[] = // urn:oasis:names:tc:SAML:2.0:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh samlconstants::SAML20MD_NS[] = // urn:oasis:names:tc:SAML:2.0:metadata
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull
};

const XMLCh samlconstants::SAML20AC_NS[] = // urn:oasis:names:tc:SAML:2.0:ac
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_a, chLatin_c, chNull
};

const XMLCh samlconstants::SAML20_PREFIX[] = UNICODE_LITERAL_4(s,a,m,l);

const XMLCh samlconstants::SAML20P_PREFIX[] = UNICODE_LITERAL_5(s,a,m,l,p);

const XMLCh samlconstants::SAML20MD_PREFIX[] = UNICODE_LITERAL_2(m,d);

const XMLCh samlconstants::SAML20AC_PREFIX[] = UNICODE_LITERAL_2(a,c);

const XMLCh samlconstants::SAML20ECP_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_S, chLatin_S, chLatin_O, chColon, chLatin_e, chLatin_c, chLatin_p, chNull
};

const XMLCh samlconstants::SAML20ECP_PREFIX[] = UNICODE_LITERAL_3(e,c,p);

const XMLCh samlconstants::SAML20DCE_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:DCE
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_D, chLatin_C, chLatin_E, chNull
};

const XMLCh samlconstants::SAML20DCE_PREFIX[] = UNICODE_LITERAL_3(D,C,E);

const XMLCh samlconstants::SAML20X500_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_X, chDigit_5, chDigit_0, chDigit_0, chNull
};

const XMLCh samlconstants::SAML20X500_PREFIX[] = { chLatin_x, chDigit_5, chDigit_0, chDigit_0 };

const XMLCh samlconstants::SAML20XACML_NS[] = // urn:oasis:names:tc:SAML:2.0:profiles:attribute:XACML
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_X, chLatin_A, chLatin_C, chLatin_M, chLatin_L, chNull
};

const XMLCh samlconstants::SAML20XACML_PREFIX[] = UNICODE_LITERAL_9(x,a,c,m,l,p,r,o,f);

const XMLCh samlconstants::SAML1MD_NS[] = // urn:oasis:names:tc:SAML:profiles:v1metadata
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_f, chLatin_i, chLatin_l, chLatin_e, chLatin_s, chColon,
  chLatin_v, chDigit_1, chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chNull
};

const XMLCh samlconstants::SAML1MD_PREFIX[] =
{ chLatin_s, chLatin_a, chLatin_m, chLatin_l, chDigit_1, chLatin_m, chLatin_d, chNull };

const XMLCh samlconstants::SAML10_PROTOCOL_ENUM[] = // urn:oasis:names:tc:SAML:1.0:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_0, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh samlconstants::SAML11_PROTOCOL_ENUM[] = // urn:oasis:names:tc:SAML:1.1:protocol
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_1, chPeriod, chDigit_1, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chNull
};

const XMLCh samlconstants::SAML20MD_QUERY_EXT_NS[] = // urn:oasis:names:tc:SAML:metadata:ext:query
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chColon,
  chLatin_e, chLatin_x, chLatin_t, chColon, chLatin_q, chLatin_u, chLatin_e, chLatin_r, chLatin_y, chNull
};

const XMLCh samlconstants::SAML20MD_QUERY_EXT_PREFIX[] = UNICODE_LITERAL_5(q,u,e,r,y);

const XMLCh samlconstants::SAML20P_THIRDPARTY_EXT_NS[] = // urn:oasis:names:tc:SAML:protocol:ext:third-party
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_p, chLatin_r, chLatin_o, chLatin_t, chLatin_o, chLatin_c, chLatin_o, chLatin_l, chColon,
  chLatin_e, chLatin_x, chLatin_t, chColon,
  chLatin_t, chLatin_h, chLatin_i, chLatin_r, chLatin_d, chDash, chLatin_p, chLatin_a, chLatin_r, chLatin_t, chLatin_y, chNull
};

const XMLCh samlconstants::SAML20P_THIRDPARTY_EXT_PREFIX[] = UNICODE_LITERAL_6(t,h,r,p,t,y);

const XMLCh samlconstants::SAML20_ATTRIBUTE_EXT_NS[] = // urn:oasis:names:tc:SAML:attribute:ext
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chColon,
  chLatin_e, chLatin_x, chLatin_t, chNull
};

const XMLCh samlconstants::SAML20_ATTRIBUTE_EXT_PREFIX[] = UNICODE_LITERAL_3(e,x,t);

const XMLCh samlconstants::SAML20MD_ENTITY_ATTRIBUTE_NS[] = // urn:oasis:names:tc:SAML:metadata:attribute
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon,
  chLatin_m, chLatin_e, chLatin_t, chLatin_a, chLatin_d, chLatin_a, chLatin_t, chLatin_a, chColon,
  chLatin_a, chLatin_t, chLatin_t, chLatin_r, chLatin_i, chLatin_b, chLatin_u, chLatin_t, chLatin_e, chNull
};

const XMLCh samlconstants::SAML20MD_ENTITY_ATTRIBUTE_PREFIX[] = UNICODE_LITERAL_6(m,d,a,t,t,r);

const XMLCh samlconstants::SAML20_DELEGATION_CONDITION_NS[] = // urn:oasis:names:tc:SAML:2.0:conditions:delegation
{ chLatin_u, chLatin_r, chLatin_n, chColon, chLatin_o, chLatin_a, chLatin_s, chLatin_i, chLatin_s, chColon,
  chLatin_n, chLatin_a, chLatin_m, chLatin_e, chLatin_s, chColon, chLatin_t, chLatin_c, chColon,
  chLatin_S, chLatin_A, chLatin_M, chLatin_L, chColon, chDigit_2, chPeriod, chDigit_0, chColon,
  chLatin_c, chLatin_o, chLatin_n, chLatin_d, chLatin_i, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chLatin_s, chColon,
  chLatin_d, chLatin_e, chLatin_l, chLatin_e, chLatin_g, chLatin_a, chLatin_t, chLatin_i, chLatin_o, chLatin_n, chNull
};

const XMLCh samlconstants::SAML20_DELEGATION_CONDITION_PREFIX[] = UNICODE_LITERAL_3(d,e,l);

const char samlconstants::SAML1_BINDING_SOAP[] = "urn:oasis:names:tc:SAML:1.0:bindings:SOAP-binding";

const char samlconstants::SAML1_PROFILE_BROWSER_ARTIFACT[] = "urn:oasis:names:tc:SAML:1.0:profiles:artifact-01";

const char samlconstants::SAML1_PROFILE_BROWSER_POST[] = "urn:oasis:names:tc:SAML:1.0:profiles:browser-post";

const char samlconstants::SAML20_BINDING_SOAP[] = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

const char samlconstants::SAML20_BINDING_PAOS[] = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";

const char samlconstants::SAML20_BINDING_URI[] = "urn:oasis:names:tc:SAML:2.0:bindings:URI";

const char samlconstants::SAML20_BINDING_HTTP_ARTIFACT[] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";

const char samlconstants::SAML20_BINDING_HTTP_POST[] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

const char samlconstants::SAML20_BINDING_HTTP_POST_SIMPLESIGN[] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign";

const char samlconstants::SAML20_BINDING_HTTP_REDIRECT[] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

const char samlconstants::SAML20_BINDING_URL_ENCODING_DEFLATE[] = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
