/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.publisher;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.Collections;

import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ca.publisher.LdapPublisher.ConnectionSecurity;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPModification;
import com.novell.ldap.LDAPSearchConstraints;
import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;

/**
 * Unit tests for {@link LdapPublisher}
 */
public class LdapPublisherUnitTest {
    
    //
    // Creating our own special LDAPConnection to test CreatIntermediateNodes() and revokeCertificates()
    //
    class TestLDAPConnection extends LDAPConnection{
        
        public LDAPEntry readResult = null;
        public int numberOfReadErrorsBeforeResult = 0;
        public boolean throwOtherLdapException = false;
        
        @Override
        public LDAPEntry read(String dn, LDAPSearchConstraints cons) throws LDAPException {
            
            if (throwOtherLdapException) throw new LDAPException( "", LDAPException.ADMIN_LIMIT_EXCEEDED, ""); 
                
            if ( numberOfReadErrorsBeforeResult > 0){
                --numberOfReadErrorsBeforeResult;
                throw new LDAPException( "", LDAPException.NO_SUCH_OBJECT, "");
            }
            return readResult;
        }

        public java.util.Vector<LDAPEntry> ldapAdds = new java.util.Vector<>();
        
        @Override
        public void add( LDAPEntry entry, LDAPConstraints cons) throws LDAPException {
            ldapAdds.add( entry);
        }

        @Override
        public void connect(String host, int port) throws LDAPException {
        }
        
        @Override
        public void bind(int version, String dn, byte[] passwd, LDAPConstraints cons) throws LDAPException {
        }

        @Override
        public void disconnect() throws LDAPException {
        }
        
        public java.util.Vector<LDAPModification> ldapMods = new java.util.Vector<>();
        
        @Override
        public void modify(String dn, LDAPModification[] mod, LDAPConstraints cons) throws LDAPException {
            for ( int i=0; i< mod.length;i++) {
                ldapMods.add(mod[i]);
            }
       }
        
        String deletedDN="";
        @Override
        public void delete(String dn, LDAPConstraints cons) throws LDAPException {
            deletedDN=dn;
        }
    }
    
    //
    // Creating our own special LdapPublisher to test revokeCertificates()
    // The only change is to provide the special TestLDAPConnection.
    //
   class TestLdapPublisher extends LdapPublisher{
        
        public TestLDAPConnection lc = new TestLDAPConnection();
        
        @Override
        protected LDAPConnection createLdapConnection() {
            return lc;
        }

    }
   
   String certTestEE1 = "MIICDzCCAXigAwIBAgIUeBPB2rs2+xA8JSv420JQlVNw2j4wDQYJKoZIhvcNAQELBQAwLTELMAkGA1UEBhMCU0UxDTALBgNVBAoMBFRlc3QxDzANBgNVBAMMBlVzZXIgMTAeFw0yNTA4MTMwNTU4MzNaFw0zNTA4MTEwNTU4MzNaMC0xCzAJBgNVBAYTAlNFMQ0wCwYDVQQKDARUZXN0MQ8wDQYDVQQDDAZVc2VyIDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMfA/lowO89zg6ORJjyJgBYJV3WYwmm/Xpuzpj3rRKeLWNcOwzqWx2ZPh/7SVOlc2K3qwOZyZEn/nnc0x/5j/uFAbTQ++jOSPFjj8EjkRt3V1/xdX0Pt0TWr6aNPWomL4ZvF6LOziyZjQamGvCBaTSdVY81YpzVjEh/PSU9PypJXAgMBAAGjLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFCqS6gl4Yfg4un2T6FAHLVCxBZjYMA0GCSqGSIb3DQEBCwUAA4GBAI8SpMwcj2ybWDlJNyk5s/qyZkRr0ejgMDL6Dx9Rp0Awy3Iij3hqjbKBrxNRazvN23r+BiHVk/QLVKDlifsSJ0C7yBSOk8nh2vL/TNsL4YWFaKhTEZFXGJX+L0voMWfHaKg0Ifknp5ie4Yk6QdDIGgloiaIetI7xx8xxUPi5IItA";
   String certTestEE2 = "MIICDzCCAXigAwIBAgIUKxVBWMKNF3DCHLfLU3exhFjMHT4wDQYJKoZIhvcNAQELBQAwLTELMAkGA1UEBhMCU0UxDTALBgNVBAoMBFRlc3QxDzANBgNVBAMMBlVzZXIgMTAeFw0yNTA4MTMwNzM1MjlaFw0zNTA4MTEwNzM1MjlaMC0xCzAJBgNVBAYTAlNFMQ0wCwYDVQQKDARUZXN0MQ8wDQYDVQQDDAZVc2VyIDEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAK8U1w4fmC89VQc4RIve998vm6bFR7E5evKj4YpY2UTrcNo0zUduFoJK5K1Koc787qLHxRq4T98iVKhcX5jMuyosfdOvh07zaqfB39JDHVd2/PMR5iZXqgRCCqGfkPUVqqsjNsLk00HOv5NU0K9o7dE+qhFd1jyUBASpCF9r0binAgMBAAGjLDAqMAkGA1UdEwQCMAAwHQYDVR0OBBYEFEF27maFG7wgk3XyfBX6ZNArPtstMA0GCSqGSIb3DQEBCwUAA4GBAFUx0k/AiEEICneY/0MVLgMVwUH0pVTxoA6vlxgCXwWaw2xc/c7v0w0l1q5iyL+zhuBjmtt2mHx156vyMciOejpOhHM+ryCCNPbkR4ZwOsNCCPH0/TNniile+hsXG93nLqRK0L64JCRKTOWRzPo1KaBVzJK4bh+d3yVw4/F78qCZ";


    @Test
    public void constructLdapDnSingle() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Collections.singleton(DNFieldExtractor.UID));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc", null));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc,C=SE", null));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,O=org", publ.constructLDAPDN("UID=abc,C=SE", "UID=def"));
        assertEquals("Wrong DN with fields={UID} ", "UID=def,O=org", publ.constructLDAPDN("C=SE", "UID=def"));
    }

    @Test
    public void constructLdapDnMultiple() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,CN=name,OU=devs,O=org", publ.constructLDAPDN("CN=name,UID=abc,givenName=john,OU=devs", "C=SE"));
    }

    @Test
    public void constructLdapDnMultipleSameType() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "UID=abc,CN=name1,CN=name2,OU=devs,OU=ejbca,O=org", publ.constructLDAPDN("CN=name1,CN=name2,UID=abc,givenName=john,OU=devs,OU=ejbca", "O=org"));
    }

    @Test
    public void constructLdapDnMultipleCustomOrder() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseCustomDnOrder(true);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "CN=name,UID=abc,OU=devs,O=org", publ.constructLDAPDN("CN=name,UID=abc,givenName=john,OU=devs", "C=SE"));
    }

    @Test
    public void constructLdapDnMultipleSameTypeCustomOrder() {
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("O=org");
        publ.setUseCustomDnOrder(true);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.UID, DNFieldExtractor.OU));
        assertEquals("Wrong DN with fields={UID} ", "CN=name1,CN=name2,UID=abc,OU=devs,OU=ejbca,O=org", publ.constructLDAPDN("CN=name1,CN=name2,OU=devs,OU=ejbca,UID=abc,givenName=john", "O=org"));
    }
    
    @Test
    public void constructLdapDn_EmptyBaseDN() {
        // Aim: With an empty Base DN, the DN will not have anything extra appended; especially not a solo ","
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.OU, DNFieldExtractor.O, DNFieldExtractor.L, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,OU=devs,OU=ejbca,O=org,L=Local,ST=Region,C=SE", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }

    @Test
    public void constructLdapDn_BlankBaseDN() {
        // Aim: A test variation of last test, but here the Base DN is "blank" (by just having a space character).
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN(" "); // A space can be used via the webform.
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.OU, DNFieldExtractor.O, DNFieldExtractor.L, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,OU=devs,OU=ejbca,O=org,L=Local,ST=Region,C=SE", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }

    @Test
    public void constructLdapDn_WithBaseDN() {
        // Aim: Check that the BaseDN (if not blank), is appended to the DN.
        final LdapPublisher publ = new LdapPublisher();
        publ.setBaseDN("dc=Root");
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.ST, DNFieldExtractor.C));
        assertEquals("Wrong Constructed LDAP DN  ", "CN=Name 1,O=org,ST=Region,C=SE,dc=Root", publ.constructLDAPDN("CN=Name 1,OU=devs,OU=ejbca,O=org,l=Local,st=Region,c=SE", "O=notused"));
    }


    @Test
    public void createIntermediateNodes_FullTreeCreated() {
        // Aim: Test the modified 'creatintermediateNodes() can build a full LDAP tree, including with DN components of DC, C, L, and ST
        //      Indirectly testing getOblectClassAttribute() as well.
        
        final LdapPublisher publ = new LdapPublisher();

        // Use a fake LDAP connection to help us test.
        TestLDAPConnection lc = new TestLDAPConnection();

        // Set 4 LDAP read failures. The createIntermediateNodes() will recursively scan to final parent node "dc=root", 
        // then will create the DN  nodes from this point.
        lc.numberOfReadErrorsBeforeResult = 4;
         
        //
        // Test creatIntermediateNodes() 
        
        try {
            publ.createIntermediateNodes( lc,  "CN=Name 1,L=Small Village,ST=Region ABC,C=SE,dc=EU,dc=Root");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // We should see 4 LDAP Add operations.
        assertEquals( "Expected 4 LDAP additions.", lc.ldapAdds.size() , 4);
        
        //
        // Check each Node being added to the LDAP
        //
        LDAPEntry le = lc.ldapAdds.get(0);
        assertTrue( "Expected the DN to be 'dc=EU,dc=Root'", le.getDN().equalsIgnoreCase("DC=EU,dc=Root"));
        assertTrue( "Expected 'objectClass=domain'", le.getAttribute("objectClass").toString().contains("domain") );
        assertEquals( "Expected 'dc=EU'", le.getAttribute("dc").getStringValue().toUpperCase(), "EU" );
        

        le = lc.ldapAdds.get(1);
        assertTrue( "Expected the DN to be 'C=SE,dc=EU,dc=Root'", le.getDN().equalsIgnoreCase("C=SE,dc=EU,dc=Root"));
        assertTrue( "Expected 'objectClass=country'", le.getAttribute("objectClass").toString().contains("country") );
        assertEquals( "Expected 'c=SE'", le.getAttribute("c").getStringValue().toUpperCase(), "SE" );
        
        
        le = lc.ldapAdds.get(2);
        assertTrue( "Expected the DN to be 'ST=Region ABC,C=SE,dc=EU,dc=Root'", le.getDN().equalsIgnoreCase("ST=Region ABC,C=SE,dc=EU,dc=Root"));
        assertTrue( "Expected 'objectClass=locality'", le.getAttribute("objectClass").toString().contains("locality") );
        assertEquals( "Expected 'ST=Region ABC'", le.getAttribute("ST").getStringValue().toLowerCase(), "region abc" );

        
        le = lc.ldapAdds.get(3);
        assertTrue( "Expected the DN to be 'L=Small Village,ST=Region ABC,C=SE,dc=EU,dc=Root'", le.getDN().equalsIgnoreCase("L=Small Village,ST=Region ABC,C=SE,dc=EU,dc=Root"));
        assertTrue( "Expected 'objectClass=locality'", le.getAttribute("objectClass").toString().contains("locality") );
        assertEquals( "Expected 'L=Small Village'", le.getAttribute("L").getStringValue().toLowerCase(), "small village" );
    }


    @Test
    public void createIntermediateNodes_NoParentNode() {
        // Aim: Testing an extreme case that there is no parent node, just the CN.
        
        final LdapPublisher publ = new LdapPublisher();

        // Use a fake LDAP connection to help us test.
        TestLDAPConnection lc = new TestLDAPConnection();
        
        //
        // Test a DN with no parent node. Result should be a simple return.
        
        try {
            publ.createIntermediateNodes( lc,  "CN=Name 1");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // We should see 0 LDAP Add operations.
        assertEquals( "Expected zeroLDAP additions.", lc.ldapAdds.size() , 0);
    }

    

    @Test
    public void createIntermediateNodes_RecursionWillAlwaysEnd() {
        // Aim: Check that the recursion in the code cannot go rouge.
        
        final LdapPublisher publ = new LdapPublisher();

        // Use a fake LDAP connection to help us test.
        TestLDAPConnection lc = new TestLDAPConnection();

        // Set huge number of LDAP read failures. The createIntermediateNodes() should only loop till parent node is ""
        lc.numberOfReadErrorsBeforeResult = 100;
         
        //
        // Test creatIntermediateNodes() will always exit when parent node is blank.
        
        try {
            publ.createIntermediateNodes( lc,  "CN=Name 1,L=Small Village,ST=Region ABC,C=SE,dc=EU,dc=Root");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", true);
        }
        
        // The numberOfReadErrorsBeforeResult will be 95; that is 100 less 5 Parent DNs.
        assertEquals("The recursive call should only happen 5 times.", lc.numberOfReadErrorsBeforeResult , 95);
        
        // We should see 5 LDAP Add operations.
        assertEquals( "Expected 5 LDAP additions.", lc.ldapAdds.size() ,5);
        
        //
        // Check the first Add operation is for 'dc=Root'.
        //
        LDAPEntry le = lc.ldapAdds.get(0);
        assertEquals( "Expected the DN to be 'dc=Root'", le.getDN().toLowerCase(), "dc=root");
        assertTrue( "Expected 'objectClass=domain'", le.getAttribute("objectClass").toString().contains("domain") );
        assertEquals( "Expected 'dc=Root'", le.getAttribute("dc").getStringValue().toLowerCase(), "root" );
        
    }


    @Test
    public void createIntermediateNodes_OtherLdapException() {
        // Aim: Checking that unexpected LDAPExceptions will abort the recursion.
        
        final LdapPublisher publ = new LdapPublisher();

        // Use a fake LDAP connection to help us test.
        TestLDAPConnection lc = new TestLDAPConnection();

        // Force an alternate Ldap Exception
        lc.throwOtherLdapException = true;
         
        //
        // Test creatIntermediateNodes() will return normally
        
        try {
            publ.createIntermediateNodes( lc,  "CN=Name 1,L=Small Village,ST=Region ABC,C=SE,dc=EU,dc=Root");
            assertTrue( "Code should have returned normally.", true);
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }

    }


    @Test
    public void revokeCertificate_TwoCertsBeforeRevocation_OneCertRemains() {
        // Aim: An LDAP Entry with two certificates, and one cert is revoked, the 'userCertificate' attribute is modified, 
        //      leaving the other certificate remaining.
        
        // Need fake LdapPublisher
       final TestLdapPublisher publ = new TestLdapPublisher();

        // Set some fake details, but we need something to respond to the TCP ping.
        publ.setHostnames("localhost");
        publ.setPort("22");   // may not work on Windows.
        publ.setConnectionSecurity( ConnectionSecurity.PLAIN);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.C));
        publ.setRemoveRevokedCertificates( true);

        // Load up the test certificate
        byte[] cert1InBytes = Base64.decode(certTestEE1); 
        byte[] cert2InBytes = Base64.decode(certTestEE2); 
 
        // Setup the fake ldap read response. The entry to have two userCertificates.
        String userDN = "CN=User 1,O=Test,c=SE";
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        LDAPAttribute certAttr = new LDAPAttribute("userCertificate;binary");
        certAttr.addValue(cert1InBytes);
        certAttr.addValue(cert2InBytes);
        attrs.add( certAttr);
        LDAPEntry le = new LDAPEntry( userDN, attrs);
        publ.lc.readResult = le;

        // Need the certificate structure
        Certificate cert=null;
       try {
            cert = CertTools.getCertfromByteArray( cert1InBytes);
        } catch (CertificateParsingException e) {
            assertTrue("Certificate encoding issue: "+e.getMessage(),false);
        }
       
        //
        // Test revokeCertificate        
        try {
            publ.revokeCertificate( null, cert, "testuser", 0, "");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // Only one attribute should have been modified
        assertEquals( "Expected 1 LDAP modification.", publ.lc.ldapMods.size() , 1);
        
        // Should be a REPLACE operation
        LDAPModification lm = publ.lc.ldapMods.get(0);
        assertEquals("LDAP operation should be REPLACE", lm.getOp(), LDAPModification.REPLACE);

        // Check that cert#1 was removed, but cert#2 remains
        LDAPAttribute la = lm.getAttribute();
        assertEquals("The replacement object should be 'userCertificate;binary", la.getName(), "userCertificate;binary");
        assertEquals("The replacement should be one cert", la.size(), 1);
        assertEquals("The replacement cert should be #2", Base64.toBase64String(la.getByteValue()),certTestEE2);
    }

    @Test
    public void revokeCertificate_OneCertBeforeRevocation_AttributeDeleted() {
        // Aim: An LDAP Entry with one certificate, and that cert is revoked, the 'userCertificate' attribute is deleted.
        
        // Need fake LdapPublisher
        final TestLdapPublisher publ = new TestLdapPublisher();

        // Set some fake details, but we need something to respond to the TCP ping.
        publ.setHostnames("localhost");
        publ.setPort("22");   // may not work on Windows.
        publ.setConnectionSecurity( ConnectionSecurity.PLAIN);
        publ.setRemoveRevokedCertificates( true);
         publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.C));

        // Load up the test certificate into ldap entry
        byte[] cert2InBytes = Base64.decode(certTestEE2); 
 
        // Setup the fake ldap read response. The entry to have two userCertificates.
        String userDN = "CN=User 1,O=Test,c=SE";
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        LDAPAttribute certAttr = new LDAPAttribute("userCertificate;binary");
        certAttr.addValue(cert2InBytes);
        attrs.add( certAttr);
        LDAPEntry le = new LDAPEntry( userDN, attrs);
        publ.lc.readResult = le;

        // Need the certificate structure
        Certificate cert=null;
        try {
            cert = CertTools.getCertfromByteArray( cert2InBytes);
        } catch (CertificateParsingException e) {
            assertTrue("Certificate encoding issue: "+e.getMessage(),false);
        }

        //
        // Test revokeCertificate        
        try {
            publ.revokeCertificate( null, cert, "testuser", 0, "");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // Only one attribute should have been modified
        assertEquals( "Expected 1 LDAP modification.", publ.lc.ldapMods.size() , 1);
        
        // Should be a DELETE operation
        LDAPModification lm = publ.lc.ldapMods.get(0);
        assertEquals("LDAP operation should be DELETE", lm.getOp(),LDAPModification.DELETE);
        
        // Check deletion was of userCertificate
        LDAPAttribute la = lm.getAttribute();
        assertEquals("The deleted object should be 'userCertificate;binary", la.getName(),"userCertificate;binary");
    }

    
    @Test
    public void revokeCertificate_TwoCertsBeforeRevocation_UserNotDeleted() {
        // Aim: An LDAP Entry with two certificate, and one cert is revoked, the Ldap entry is not deleted even if the option is enabled.
       
        // Need fake LdapPublisher
        final TestLdapPublisher publ = new TestLdapPublisher();

        // Set some fake details, but we need something to respond to the TCP ping.
        publ.setHostnames("localhost");
        publ.setPort("22");   // may not work on Windows.
        publ.setConnectionSecurity( ConnectionSecurity.PLAIN);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.C));
        publ.setRemoveRevokedCertificates( true);
        publ.setRemoveUsersWhenCertRevoked(true);

        // Load up the test certificate
        byte[] cert1InBytes = Base64.decode(certTestEE1); 
        byte[] cert2InBytes = Base64.decode(certTestEE2); 
 
        // Setup the fake ldap read response. The entry to have two userCertificates.
        String userDN = "CN=User 1,O=Test,c=SE";
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        LDAPAttribute certAttr = new LDAPAttribute("userCertificate;binary");
        certAttr.addValue(cert1InBytes);
        certAttr.addValue(cert2InBytes);
        attrs.add( certAttr);
        LDAPEntry le = new LDAPEntry( userDN, attrs);
        publ.lc.readResult = le;

        // Need the certificate structure
        Certificate cert=null;
       try {
            cert = CertTools.getCertfromByteArray( cert2InBytes);
        } catch (CertificateParsingException e) {
            assertTrue("Certificate encoding issue: "+e.getMessage(),false);
        }
       
        //
        // Test revokeCertificate        
        try {
            publ.revokeCertificate( null, cert, "testuser", 0, "");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // Only one attribute should have been modified
        assertEquals( "Expected 1 LDAP modification.", publ.lc.ldapMods.size() , 1);
        
        // Should be a REPLACE operation
        LDAPModification lm = publ.lc.ldapMods.get(0);
        assertEquals("LDAP operation should be REPLACE", lm.getOp(), LDAPModification.REPLACE);

        // Check that cert#2 was removed, but cert#1 remains
        LDAPAttribute la = lm.getAttribute();
        assertEquals("The replacement object should be 'userCertificate;binary", la.getName(), "userCertificate;binary");
        assertEquals("The replacement should be one cert", la.size(), 1);
        assertEquals("The replacement cert should be #1", Base64.toBase64String(la.getByteValue()), certTestEE1);
    }

    @Test
    public void revokeCertificate_OneCertsBeforeRevocation_UserNowDeleted() {
        // Aim: An LDAP Entry with one certificate, and that cert is revoked, the Ldap entry is deleted if the option is enabled.
        
        // Need fake LdapPublisher
        final TestLdapPublisher publ = new TestLdapPublisher();

        // Set some fake details, but we need something to respond to the TCP ping.
        publ.setHostnames("localhost");
        publ.setPort("22");   // may not work on Windows.
        publ.setConnectionSecurity( ConnectionSecurity.PLAIN);
        publ.setRemoveRevokedCertificates( true);
        publ.setRemoveUsersWhenCertRevoked(true);
        publ.setUseFieldInLdapDN(Arrays.asList(DNFieldExtractor.CN, DNFieldExtractor.O, DNFieldExtractor.C));

        // Load up the test certificate into ldap entry
        byte[] cert2InBytes = Base64.decode(certTestEE2); 
 
        // Setup the fake ldap read response. The entry to have two userCertificates.
        String userDN = "CN=User 1,O=Test,c=SE";
        LDAPAttributeSet attrs = new LDAPAttributeSet();
        LDAPAttribute certAttr = new LDAPAttribute("userCertificate;binary");
        certAttr.addValue(cert2InBytes);
        attrs.add( certAttr);
        LDAPEntry le = new LDAPEntry( userDN, attrs);
        publ.lc.readResult = le;

        // Need the certificate structure
        Certificate cert=null;
        try {
            cert = CertTools.getCertfromByteArray( cert2InBytes);
        } catch (CertificateParsingException e) {
            assertTrue("Certificate encoding issue: "+e.getMessage(),false);
        }

        //
        // Test revokeCertificate        
        try {
            publ.revokeCertificate( null, cert, "testuser", 0, "");
        } catch (PublisherException e) {
            assertTrue( "Exception not expected.", false);
        }
        
        // Only one attribute should have been modified
        assertEquals( "Expected 1 LDAP modification.", publ.lc.ldapMods.size() , 1);
        
        // Should be a DELETE operation
        LDAPModification lm = publ.lc.ldapMods.get(0);
        assertEquals("LDAP operation should be DELETE", lm.getOp(),LDAPModification.DELETE);
        
        // Check deletion was of userCertificate
        LDAPAttribute la = lm.getAttribute();
        assertEquals("The deleted object should be 'userCertificate;binary", la.getName(),"userCertificate;binary");
        
        // The user should have been deleted
        assertEquals("Expecting the User entry in ldap to be deleted", userDN.toLowerCase(), publ.lc.deletedDN.toLowerCase());
    }

    
}
