/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.cesecore.certificates.certificate.certextensions.DummyCertificateExtension;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * @version $Id$
 */
public class AvailableCustomCertExtensionsConfigTest {
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    
    private AvailableCustomCertificateExtensionsConfiguration cceConfigBackup;
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "AvailableCustomCertExtensionsConfigTest"));

    @Before
    public void setUp() {
        cceConfigBackup = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
    }
    
    @After
    public void tearDown() throws Exception {
        globalConfigSession.saveConfiguration(alwaysAllowToken, cceConfigBackup);
    }
    
    @Test
    public void testCustomCertExtensionsConfiguration() throws Exception{
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();
        
        Properties props = new Properties();
        props.put("translatable", "FALSE");
        props.put("encoding", "DERPRINTABLESTRING");
        props.put("value", "Test 123");
        cceConfig.addCustomCertExtension(1, "1.2.3.4", "TESTEXTENSION", BasicCertificateExtension.class.getName(), true, true, props);
        
        props = new Properties();
        props.put("translatable", "FALSE");
        props.put("encoding", "DERPRINTABLESTRING");
        props.put("value", "Test 123");
        cceConfig.addCustomCertExtension(2, "2.2.3.4", "TESTEXTENSION2", BasicCertificateExtension.class.getName(), true, true, props);

        props = new Properties();
        props.put("translatable", "TRUE");
        props.put("value", "Test 321");
        cceConfig.addCustomCertExtension(3, "3.2.3.4", "TESTEXTENSION3", DummyCertificateExtension.class.getName(), false, true, props);
        
        CustomCertificateExtension ext = cceConfig.getCustomCertificateExtension(1);
        assertNotNull(ext);
        assertEquals(1, ext.getId());
        assertEquals("1.2.3.4", ext.getOID());
        assertEquals("TESTEXTENSION", ext.getDisplayName());
        assertTrue(ext instanceof BasicCertificateExtension);
        assertTrue(ext.isCriticalFlag());
        assertFalse("The property 'translatable' should be 'False'", Boolean.parseBoolean((String) ext.getProperties().get("translatable")));
        assertTrue(getObject(ext.getValueEncoded(null, null, null, null, null, null)) instanceof DERPrintableString);
        assertEquals("Test 123", ((DERPrintableString) getObject(ext.getValueEncoded(null, null, null, null, null, null))).getString());
        
        ext = cceConfig.getCustomCertificateExtension(3);
        assertNotNull(ext);
        assertEquals(3 , ext.getId());
        assertEquals("3.2.3.4", ext.getOID());
        assertEquals("TESTEXTENSION3", ext.getDisplayName());
        assertTrue(ext instanceof DummyCertificateExtension);
        assertFalse(ext.isCriticalFlag());
        assertTrue("The property 'translatable' should be 'True'", Boolean.parseBoolean((String) ext.getProperties().get("translatable")));
        assertTrue(getObject(ext.getValueEncoded(null, null, null, null, null, null)) instanceof DERIA5String);
        assertEquals("Test 321", ((DERIA5String) getObject(ext.getValueEncoded(null, null, null, null, null, null))).getString());

        // Test that non-existing key return null
        ext = cceConfig.getCustomCertificateExtension(300);
        assertNull(ext);
        
        // test removal
        cceConfig.removeCustomCertExtension(1);
        ext = cceConfig.getCustomCertificateExtension(1);
        assertNull(ext);
        
    }
    
    private ASN1Encodable getObject(byte[] valueEncoded) throws IOException {
        ASN1InputStream in = new ASN1InputStream(new ByteArrayInputStream(valueEncoded));
        try {
            return in.readObject();
        } finally {
            in.close();
        }
    }
    
    @Test
    public void testAddingManyCustomCertExtensions() throws Exception {
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = new AvailableCustomCertificateExtensionsConfiguration();

        Properties props = new Properties();
        props.put("value", "Test 321"); 
        String oid, displayName;
        for(int i=0; i<150; i++) {
            oid = "1.3.15." + i + ".33.12";  // random string that looks like an oid
            displayName = "Readable name of CustomCertExtension with oid " + oid;
            cceConfig.addCustomCertExtension(i, oid, displayName, BasicCertificateExtension.class.getName(), false, true, props);
        }
                
        globalConfigSession.saveConfiguration(alwaysAllowToken, cceConfig);
        AvailableCustomCertificateExtensionsConfiguration cceConfig2 = (AvailableCustomCertificateExtensionsConfiguration) globalConfigSession.
                getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);

        for(int i=0; i<150; i++) {
            oid = "1.3.15." + i + ".33.12";  // random string that looks like an oid
            CustomCertificateExtension ext = cceConfig2.getCustomCertificateExtension(i);
            displayName = "Readable name of CustomCertExtension with oid " + oid;
            assertNotNull(ext);
            assertEquals(oid, ext.getOID());
            assertEquals(displayName, ext.getDisplayName());
            assertTrue(ext instanceof BasicCertificateExtension );
            assertFalse(ext.isCriticalFlag());
            assertNull(ext.getProperties().get("translatable"));
        }
    }
    
}
