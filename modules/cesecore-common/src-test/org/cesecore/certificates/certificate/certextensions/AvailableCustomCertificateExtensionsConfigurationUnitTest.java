/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.certextensions;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.junit.Test;


/**
 * Unit test of {@link AvailableCustomCertificateExtensionsConfiguration}.
 * @see org.cesecore.certificates.certificate.AvailableCustomCertExtensionsConfigTest AvailableCustomCertExtensionsConfigTest (related system test)
 * @version $Id$
 */
public class AvailableCustomCertificateExtensionsConfigurationUnitTest {

    private static final Logger log = Logger.getLogger(AvailableCustomCertificateExtensionsConfigurationUnitTest.class);

    /** Encoded DEROctetString with 2 byte value: AB CD */
    private static final byte[] EXPECTED_ENCODED_VALUE = { 0x04, 0x02, (byte) 0xAB, (byte) 0xCD };

    /**
     * Tests the method that is used for parsing old certextensions.properties files from EJBCA 6.3.x and earlier.
     */
    @Test
    public void testUpgradeParsing() throws Exception {
        log.trace(">testUpgradeParsing");
        final Properties oldFileProperties = new Properties();
        oldFileProperties.put("id123.oid", " 2.999.123 ");
        oldFileProperties.put("id123.classpath", " org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension ");
        oldFileProperties.put("id123.displayname", " My Extension ");
        oldFileProperties.put("id123.used", " tRuE ");
        oldFileProperties.put("id123.translatable", " tRuE ");
        oldFileProperties.put("id123.critical", " FaLsE ");
        // BasicCertificateExtension properties
        oldFileProperties.put("id123.property.encoding", " DeRoCtEtStRiNg  ");
        oldFileProperties.put("id123.property.dynamic", " FaLsE ");
        oldFileProperties.put("id123.property.value", "aBcD"); // value did not allow padding
        CertificateExtension upgraded = AvailableCustomCertificateExtensionsConfiguration.getCertificateExtensionFromFile(123, oldFileProperties);
        log.debug("Properties after upgrade: " + upgraded.getProperties());
        assertEquals("2.999.123", upgraded.getOID());
        assertEquals("My Extension", upgraded.getDisplayName());
        assertTrue("'Required' is the default. Was false.", upgraded.isRequiredFlag());
        assertFalse("Wrong value of 'Critical'", upgraded.isCriticalFlag());
        assertEquals("Wrong value of 'translatable' property", true, upgraded.getProperties().get("translatable"));
        final EndEntityInformation dummyEndEntity = new EndEntityInformation();
        dummyEndEntity.setDN("CN=Dummy AvailableCustomCertificateExtensionsConfigurationUnitTest");
        final byte[] valueEncoded = upgraded.getValueEncoded(dummyEndEntity, null, new CertificateProfile(), /*userPublicKey*/null, /*caPublicKey*/null, /*validity*/null);
        assertArrayEquals("Wrong encoded value.", EXPECTED_ENCODED_VALUE, valueEncoded);
        log.trace("<testUpgradeParsing");
        
    }
}
