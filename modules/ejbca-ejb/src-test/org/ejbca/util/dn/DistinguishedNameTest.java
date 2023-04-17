/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.dn;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.ldap.Rdn;

import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.certificate.DnComponents;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/** Tests for DistinguishedName class.
 * 
 * @version $Id$
 */
public class DistinguishedNameTest {
    
    private static final String DN = "cn=David Galichet,o=Fimasys,email=dgalichet@fimasys.fr," 
        + "g=M,email=david.galichet@fimasys.fr";
    private static final String OTHER_DN = "o=Linagora,email=dgalichet@linagora.fr,ou=Linagora Secu," 
        + "l=Paris,email=david.galichet@linagora.com,email=dgalichet@linagora.com";
  
    private static final String SUBJECT_ALT_NAME = "RFC822NAME=vkn@linagora.com,IPADDRESS=208.77.188.166";
    private static final String OTHER_SUBJECT_ALT_NAME = "RFC822NAME=linagora.mail@linagora.com,IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
    DistinguishedName subjectAltName = null;
    DistinguishedName otherSubjectAltName = null;

    @Before
    public void setUp() throws Exception {
        otherSubjectAltName = new DistinguishedName(OTHER_SUBJECT_ALT_NAME);
    }

    @Test
    public void testCreateDistinguishedName() throws Exception {
        final String dnString = "CN=User Usersson, OU=Unit1, OU=Unit2, OU=Unit3, O=Org1, C=SE";
        final DistinguishedName dn1 = new DistinguishedName(dnString);
        assertEquals("CN=User Usersson, OU=Unit1, OU=Unit2, OU=Unit3, O=Org1, C=SE", dn1.toString());
        final List<Rdn> dnRdnList = new ArrayList<>();
        dnRdnList.add(new Rdn("CN", "User Usersson"));
        dnRdnList.add(new Rdn("OU", "Unit1"));
        dnRdnList.add(new Rdn("OU", "Unit2"));
        dnRdnList.add(new Rdn("OU", "Unit3"));
        dnRdnList.add(new Rdn("O", "Org1"));
        dnRdnList.add(new Rdn("C", "SE"));
        final DistinguishedName dn2 = new DistinguishedName(dnRdnList);
        assertEquals("C=SE,O=Org1,OU=Unit3,OU=Unit2,OU=Unit1,CN=User Usersson", dn2.toString());
        Collections.reverse(dnRdnList);
        final DistinguishedName dn3 = new DistinguishedName(dnRdnList);
        assertEquals("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", dn3.toString());
        final DistinguishedName dn4 = new DistinguishedName("");
        assertEquals("Empty should be empty...", "", dn4.toString());
        final DistinguishedName dn5 = new DistinguishedName(Collections.emptyList());
        assertEquals("Empty should be empty...", "", dn5.toString());
        
    }

    @Test
    public void testGetRdn() throws Exception {
        final DistinguishedName dn = createNewDN();
        assertEquals(dn.getRdn("cn"), new Rdn("cn", "David Galichet"));
        assertEquals(dn.getRdn("email", 1), new Rdn("email", "dgalichet@fimasys.fr"));
        assertEquals(dn.getRdn("email", 0), new Rdn("email", "david.galichet@fimasys.fr"));
        assertNull(dn.getRdn("email", 2));
    }

    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge without override.
     */
    @Test
    public void testMergeDnWithoutOverride() throws Exception {

        // This returns slightly different between JDK 7 and JDK 8, but we only support >=8 now
        final String EXPECTED_DN_JDK8 = "cn=David Galichet,o=Fimasys,email=dgalichet@fimasys.fr,"
                + "g=M,email=david.galichet@fimasys.fr,ou=Linagora Secu,l=Paris,email=dgalichet@linagora.com";
        final DistinguishedName dn = createNewDN();
        // We have two email in the DN and three in the OTHER_DN, that means two will be untouched as we do not use override, 
        // and one new (the last one in OTHER_NAME) will be added in the end
        final DistinguishedName newDn = dn.mergeDN(new DistinguishedName(OTHER_DN), false, null);
        assertEquals(EXPECTED_DN_JDK8, newDn.toString());
        
        final DistinguishedName ett = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName ettRet = ett.mergeDN(ett, false, null);
        assertEquals("Merging with itself should not change anything", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", ettRet.toString());

        final DistinguishedName tva = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName tre = new DistinguishedName("OU=Unit4,OU=Unit5");
        final DistinguishedName tvaRet = tva.mergeDN(tre, false, null);
        assertEquals("Merged OUs should not have been overridden", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", tvaRet.toString());
        final DistinguishedName treRet = tre.mergeDN(tva, false, null);
        assertEquals("Merged OUs should not have been overridden", "OU=Unit4,OU=Unit5,CN=User Usersson,OU=Unit3,O=Org1,C=SE", treRet.toString());

        final DistinguishedName fyra = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName fem  = new DistinguishedName("OU=Unit4,OU=Unit5,OU=Unit6,OU=Unit7");
        final DistinguishedName fyraRet = fyra.mergeDN(fem, false, null);
        assertEquals("Merged OUs should not have been overridden, and added", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE,OU=Unit7", fyraRet.toString());
        final DistinguishedName femRet = fem.mergeDN(fyra, false, null);
        assertEquals("Merged OUs should not have been overridden, and added", "OU=Unit4,OU=Unit5,OU=Unit6,OU=Unit7,CN=User Usersson,O=Org1,C=SE", femRet.toString());

        final DistinguishedName sex = new DistinguishedName("EMAIL=foo@bar.com,OU=MyOrgU");
        final DistinguishedName sju  = new DistinguishedName("CN=Name2,OU=Unit1,OU=Unit2,C=SE");
        final DistinguishedName sexRet = sex.mergeDN(sju, false, null);
        assertEquals("Merged with E didn't work properly", "EMAIL=foo@bar.com,OU=MyOrgU,CN=Name2,OU=Unit2,C=SE", sexRet.toString());
        final DistinguishedName sjuRet = sju.mergeDN(sex, false, null);
        assertEquals("Merged with E didn't work properly", "CN=Name2,OU=Unit1,OU=Unit2,C=SE,EMAIL=foo@bar.com", sjuRet.toString());

        final DistinguishedName atta = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1");
        final DistinguishedName nio = new DistinguishedName("");
        final DistinguishedName attaRet = atta.mergeDN(nio, false, null);
        assertEquals("Merged with empty didn't work properly", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1", attaRet.toString());
        final DistinguishedName nioRet = nio.mergeDN(atta, false, null);
        assertEquals("Merged with empty didn't work properly", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1", nioRet.toString());

    }

    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge with override.
     */
    @Test
   public void testMergeDnWithOverride() throws Exception {

        // This returns slightly different between JDK 7 and JDK 8, but we only support >=8 now
        final String EXPECTED_DN_JDK8 = "cn=David Galichet,o=Linagora,email=dgalichet@linagora.fr,"
                + "g=M,email=david.galichet@linagora.com,ou=Linagora Secu,l=Paris,email=dgalichet@linagora.com";

        final DistinguishedName dn = createNewDN();
        final DistinguishedName newDn = dn.mergeDN(new DistinguishedName(OTHER_DN), true, null);
        assertEquals(EXPECTED_DN_JDK8, newDn.toString());
        
        final DistinguishedName ett = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName ettRet = ett.mergeDN(ett, true, null);
        assertEquals("Merging with itself should not change anything", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE", ettRet.toString());

        final DistinguishedName tva = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName tre = new DistinguishedName("OU=Unit4,OU=Unit5");
        final DistinguishedName tvaRet = tva.mergeDN(tre, true, null);
        assertEquals("Merged OUs should have overridden", "CN=User Usersson,OU=Unit4,OU=Unit5,OU=Unit3,O=Org1,C=SE", tvaRet.toString());
        final DistinguishedName treRet = tre.mergeDN(tva, true, null);
        assertEquals("Merged OUs should have overridden", "OU=Unit1,OU=Unit2,CN=User Usersson,OU=Unit3,O=Org1,C=SE", treRet.toString());

        final DistinguishedName fyra = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,O=Org1,C=SE");
        final DistinguishedName fem  = new DistinguishedName("OU=Unit4,OU=Unit5,OU=Unit6,OU=Unit7");
        final DistinguishedName fyraRet = fyra.mergeDN(fem, true, null);
        assertEquals("Merged OUs should have overridden, and added", "CN=User Usersson,OU=Unit4,OU=Unit5,OU=Unit6,O=Org1,C=SE,OU=Unit7", fyraRet.toString());
        final DistinguishedName femRet = fem.mergeDN(fyra, true, null);
        assertEquals("Merged OUs should have overridden, and added", "OU=Unit1,OU=Unit2,OU=Unit3,OU=Unit7,CN=User Usersson,O=Org1,C=SE", femRet.toString());
        
        final DistinguishedName sex = new DistinguishedName("EMAIL=foo@bar.com,OU=MyOrgU");
        final DistinguishedName sju  = new DistinguishedName("CN=Name2,OU=Unit1,OU=Unit2,C=SE");
        final DistinguishedName sexRet = sex.mergeDN(sju, true, null);
        assertEquals("Merged with E didn't work properly", "EMAIL=foo@bar.com,OU=Unit1,CN=Name2,OU=Unit2,C=SE", sexRet.toString());
        final DistinguishedName sjuRet = sju.mergeDN(sex, true, null);
        assertEquals("Merged with E didn't work properly", "CN=Name2,OU=MyOrgU,OU=Unit2,C=SE,EMAIL=foo@bar.com", sjuRet.toString());
        
        final DistinguishedName atta = new DistinguishedName("CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1");
        final DistinguishedName nio = new DistinguishedName("");
        final DistinguishedName attaRet = atta.mergeDN(nio, true, null);
        assertEquals("Merged with empty didn't work properly", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1", attaRet.toString());
        final DistinguishedName nioRet = nio.mergeDN(atta, true, null);
        assertEquals("Merged with empty didn't work properly", "CN=User Usersson,OU=Unit1,OU=Unit2,OU=Unit3,C=SE,O=Org1", nioRet.toString());
    }

    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge without override.
     */
    @Test
    public void testMergeSubjectAltNameWithoutOverrideNotUsingEntityEmail() throws Exception {

        final String EXPECTED = "RFC822NAME=vkn@linagora.com,IPADDRESS=208.77.188.166,UNIFORMRESOURCEID=other.uri";
        subjectAltName = createNewSubjectAltName();
        Map<String, String> dnMap = new HashMap<String, String>();
        dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
        DistinguishedName altName = subjectAltName.mergeDN(otherSubjectAltName, false, dnMap);

        assertEquals(3, altName.size());

        assertEquals(EXPECTED, altName.toString());
    }

    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge without override.
     */
    @Test
    public void testMergeSubjectAltNameWithoutOverrideUsingEntityEmail() throws Exception {

    	final String EXPECTED = "RFC822NAME=vkn@linagora.com,IPADDRESS=208.77.188.166,UNIFORMRESOURCEID=other.uri";
        subjectAltName = createNewSubjectAltName();
        Map<String, String> dnMap = new HashMap<String, String>();
        dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
        DistinguishedName altName = subjectAltName.mergeDN(otherSubjectAltName, false, dnMap);

        assertEquals(EXPECTED, altName.toString());
    }
    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge with override.
     */
    @Test
    public void testMergeSubjectAltNameWithOverrideNotUsingEntityEmail() throws Exception {

    	final String EXPECTED = "RFC822NAME=linagora.mail@linagora.com,IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
        subjectAltName = createNewSubjectAltName();
        Map<String, String> dnMap = new HashMap<String, String>();
        DistinguishedName altName = subjectAltName.mergeDN(otherSubjectAltName, true, dnMap);

        assertEquals(EXPECTED, altName.toString());
    }
    /**
     * Test of mergeDN method, of class DistinguishedName.
     * This version tests the merge with override.
     */
    @Test
    public void testMergeSubjectAltNameWithOverrideUsingEntityEmail() throws Exception {
        final String _OTHER_SUBJECT_ALT_NAME = "IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";

    	final String EXPECTED = "RFC822NAME=entitymail@linagora.com,IPADDRESS=777.77.777.777,UNIFORMRESOURCEID=other.uri";
        DistinguishedName san = new DistinguishedName(_OTHER_SUBJECT_ALT_NAME);
        subjectAltName = createNewSubjectAltName();
        Map<String, String> dnMap = new HashMap<String, String>();
        dnMap.put(DnComponents.RFC822NAME, "entitymail@linagora.com");
        DistinguishedName altName = subjectAltName.mergeDN(san, true, dnMap);

        assertEquals(EXPECTED, altName.toString());
    }

    private DistinguishedName createNewDN() throws Exception {
        return new DistinguishedName(DN);
    }

    private DistinguishedName createNewSubjectAltName() throws Exception {
        return new DistinguishedName(SUBJECT_ALT_NAME);
    }
}
