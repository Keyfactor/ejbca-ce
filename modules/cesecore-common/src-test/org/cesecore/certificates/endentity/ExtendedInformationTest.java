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
package org.cesecore.certificates.endentity;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.junit.Test;


/**
 * Unit tests for the EndEntity and ExtendedInformation classes.
 *
 * @version $Id$
 *
 */
public class ExtendedInformationTest {

    /** A test P10 encoded as a single line of Base64 */
    public static final String pkcs10 =
            "MIIBkzCB/QIBADBUMQswCQYDVQQGEwJzZTETMBEGA1UECBMKU29tZS1TdGF0ZTEh"
            +"MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQ0wCwYDVQQDEwRURVNU"
            +"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC6zGAfzcf8+ECqvI6r2z22fI9h"
            +"pVTPWkY+vpw6w6ilzhqeMJslAQG5WogOc+NpWrGLAd8UCN2AicQE1p5dFKN8URF0"
            +"3eyNIXTTveQqzcAYaFHAuD2Ua1a3W9vbnPAm2NSiD3keeFMgXZqqFtnEqU/4XvA6"
            +"ClrEMu5/W20N3fKyVwIDAQABoAAwDQYJKoZIhvcNAQEEBQADgYEASbGs+s5PjTYW"
            +"vYQ0OOLYuNZcV2uj56FVP4jjaxed6SNC3XNrsJcqoBIUT14OTGvo+kt/Du3X5src"
            +"sLtaUfVr74y1FhDq55fqAY5+k0IpJVYGlOVsAAcx5O2jUKbxZHBSQnyVBLKczITY"
            +"PfoNI8s9NXa/fIfqp56llOPzDy3OcHc=";

    @Test
    public void testExtendedInformationCSR() {
        // Test basic function, latest version->latest version
        ExtendedInformation ei = new ExtendedInformation();
        ei.setCertificateRequest(Base64.decode(pkcs10.getBytes(StandardCharsets.UTF_8)));
        assertEquals(pkcs10, new String(Base64.encode(ei.getCertificateRequest()), StandardCharsets.UTF_8));
        // Test by hardcoding in the base64 encoded data as string, to ensure we can read such data
        // (even if the current implementation changed)
        ExtendedInformation ei2 = new ExtendedInformation();
        ei2.setMapData("CERTIFICATE_REQUEST", pkcs10);
        assertEquals(pkcs10, new String(Base64.encode(ei2.getCertificateRequest()), StandardCharsets.UTF_8));
        // Test null
        ExtendedInformation ei3 = new ExtendedInformation();
        ei3.setMapData("FOO", pkcs10);
        assertNull(ei3.getCertificateRequest());
        // Test by hardcoding in the binary encoded data, to ensure we can read such data
        // As it was stored before EJBCA 6.8.0
        ExtendedInformation ei4 = new ExtendedInformation();
        LinkedHashMap<String,Object> map = new LinkedHashMap<>();
        map.put(UpgradeableDataHashMap.VERSION, 4.0F);
        map.put("CERTIFICATE_REQUEST", Base64.decode(pkcs10.getBytes(StandardCharsets.UTF_8)));
        ei4.setData(map);
        assertEquals(pkcs10, new String(Base64.encode(ei4.getCertificateRequest()), StandardCharsets.UTF_8));
    }

    @Test
    public void testSetGetCopyFields() {
        final Integer approvalRequestId = 1;
        final String certificateEndTime = "2020-01-01T12:00:00+00:00";
        final byte[] certificateRequest = new byte[] { 0x1, 0x2, 0x3 };
        final BigInteger certificateSerialNumber = new BigInteger("13813134560128420686215030629780757563");
        final String customDataKey = "customDataKey";
        final String customDataValue = "customDataValue";
        final String customExtensionDataKey = "customExtensionDataKey";
        final String customExtensionDataValue = "customExtensionDataValue";
        final Integer issuanceRevocationReason = 2;
        final String keyStoreSubAlgorithmType = "4096";
        final String keyStoreAlgorithm = "RSA";
        final String mapDataKey = "mapDataKey";
        final String mapDataValue = "mapDataValue";
        final Integer maxLoginAttempts = 3;
        final List<String> nameConstraintsExcluded = Arrays.asList(new String[] { "a", "b", "c" });
        final List<String> nameConstraintsPermitted = Arrays.asList(new String[] { "d", "e", "f" });
        final Integer remainingLoginAttempts = 5;
        final String subjectDirectoryAttributes = "subjectDirectoryAttributes";

        final ExtendedInformation extendedInformation = new ExtendedInformation();
        extendedInformation.setAddEndEntityApprovalRequestId(approvalRequestId);
        extendedInformation.setCertificateEndTime(certificateEndTime);
        extendedInformation.setCertificateRequest(certificateRequest);
        extendedInformation.setCertificateSerialNumber(certificateSerialNumber);
        extendedInformation.setCustomData(customDataKey, customDataValue);
        extendedInformation.setExtensionData(customExtensionDataKey, customExtensionDataValue);
        extendedInformation.setIssuanceRevocationReason(issuanceRevocationReason);
        extendedInformation.setKeyStoreAlgorithmSubType(keyStoreSubAlgorithmType);
        extendedInformation.setKeyStoreAlgorithmType(keyStoreAlgorithm);
        extendedInformation.setMapData(mapDataKey, mapDataValue);
        extendedInformation.setMaxLoginAttempts(maxLoginAttempts);
        extendedInformation.setNameConstraintsExcluded(nameConstraintsExcluded);
        extendedInformation.setNameConstraintsPermitted(nameConstraintsPermitted);
        extendedInformation.setRemainingLoginAttempts(remainingLoginAttempts);
        extendedInformation.setSubjectDirectoryAttributes(subjectDirectoryAttributes);

        assertEquals(approvalRequestId, extendedInformation.getAddEndEntityApprovalRequestId());
        assertEquals(certificateEndTime, extendedInformation.getCertificateEndTime());
        assertArrayEquals(certificateRequest, extendedInformation.getCertificateRequest());
        assertEquals(certificateSerialNumber, extendedInformation.certificateSerialNumber());
        assertEquals(customDataValue, extendedInformation.getCustomData(customDataKey));
        assertEquals(customExtensionDataValue, extendedInformation.getExtensionData(customExtensionDataKey));
        assertEquals(issuanceRevocationReason, (Integer) extendedInformation.getIssuanceRevocationReason());
        assertEquals(keyStoreSubAlgorithmType, extendedInformation.getKeyStoreAlgorithmSubType());
        assertEquals(keyStoreAlgorithm, extendedInformation.getKeyStoreAlgorithmType());
        assertEquals(mapDataValue, extendedInformation.getMapData(mapDataKey));
        assertEquals(maxLoginAttempts, (Integer) extendedInformation.getMaxLoginAttempts());
        assertEquals(nameConstraintsExcluded, extendedInformation.getNameConstraintsExcluded());
        assertEquals(nameConstraintsPermitted, extendedInformation.getNameConstraintsPermitted());
        assertEquals(remainingLoginAttempts, (Integer) extendedInformation.getRemainingLoginAttempts());
        assertEquals(subjectDirectoryAttributes, extendedInformation.getSubjectDirectoryAttributes());

        final ExtendedInformation extendedInformation2 = new ExtendedInformation(extendedInformation);
        assertEquals(approvalRequestId, extendedInformation2.getAddEndEntityApprovalRequestId());
        assertEquals(certificateEndTime, extendedInformation2.getCertificateEndTime());
        assertArrayEquals(certificateRequest, extendedInformation2.getCertificateRequest());
        assertEquals(certificateSerialNumber, extendedInformation2.certificateSerialNumber());
        assertEquals(customDataValue, extendedInformation2.getCustomData(customDataKey));
        assertEquals(customExtensionDataValue, extendedInformation2.getExtensionData(customExtensionDataKey));
        assertEquals(issuanceRevocationReason, (Integer) extendedInformation2.getIssuanceRevocationReason());
        assertEquals(keyStoreSubAlgorithmType, extendedInformation2.getKeyStoreAlgorithmSubType());
        assertEquals(keyStoreAlgorithm, extendedInformation2.getKeyStoreAlgorithmType());
        assertEquals(mapDataValue, extendedInformation2.getMapData(mapDataKey));
        assertEquals(maxLoginAttempts, (Integer) extendedInformation2.getMaxLoginAttempts());
        assertEquals(nameConstraintsExcluded, extendedInformation2.getNameConstraintsExcluded());
        assertEquals(nameConstraintsPermitted, extendedInformation2.getNameConstraintsPermitted());
        assertEquals(remainingLoginAttempts, (Integer) extendedInformation2.getRemainingLoginAttempts());
        assertEquals(subjectDirectoryAttributes, extendedInformation2.getSubjectDirectoryAttributes());
    }

    @Test
    public void testIntegerFieldsAsStrings() {
        final ExtendedInformation extendedInformation = new ExtendedInformation();
        final String remainingLoginAttempts = "1";
        final String maxFailedLoginAttempts = "2";
        extendedInformation.getRawData().put("remainingloginattempts", remainingLoginAttempts);
        extendedInformation.getRawData().put("maxfailedloginattempts", maxFailedLoginAttempts);
        assertEquals(Integer.valueOf(remainingLoginAttempts), (Integer) extendedInformation.getRemainingLoginAttempts());
        assertEquals(Integer.valueOf(maxFailedLoginAttempts), (Integer) extendedInformation.getMaxLoginAttempts());
    }

    @Test
    public void parseCabfOrganizationIdentifierVatScheme() {
        final ExtendedInformation extendedInformation = new ExtendedInformation();
        extendedInformation.setCabfOrganizationIdentifier("VATSE-556677123401");
        assertEquals("VATSE-556677123401", extendedInformation.getCabfOrganizationIdentifier());
        assertEquals("Wrong scheme identifier was extracted.", "VAT", extendedInformation.getCabfRegistrationSchemeIdentifier());
        assertEquals("Wrong country code was extracted.", "SE", extendedInformation.getCabfRegistrationCountry());
        assertNull("State or Province should be null", extendedInformation.getCabfRegistrationStateOrProvince());
        assertEquals("Wrong registration reference was extracted.", "556677123401", extendedInformation.getCabfRegistrationReference());
    }

    @Test
    public void parseCabfOrganizationIdentifierPsbScheme() {
        final ExtendedInformation extendedInformation = new ExtendedInformation();
        extendedInformation.setCabfOrganizationIdentifier("PSDBE-NBB-1234.567.890");
        assertEquals("PSDBE-NBB-1234.567.890", extendedInformation.getCabfOrganizationIdentifier());
        assertEquals("Wrong scheme identifier was extracted.", "PSD", extendedInformation.getCabfRegistrationSchemeIdentifier());
        assertEquals("Wrong country code was extracted.", "BE", extendedInformation.getCabfRegistrationCountry());
        assertNull("State or Province should be null", extendedInformation.getCabfRegistrationStateOrProvince());
        assertEquals("Wrong registration reference was extracted.", "NBB-1234.567.890", extendedInformation.getCabfRegistrationReference());
    }

    @Test
    public void parseCabfOrganizationIdentifierNtrWithState() {
        final ExtendedInformation extendedInformation = new ExtendedInformation();
        extendedInformation.setCabfOrganizationIdentifier("NTRUS+CA-12345678");
        assertEquals("NTRUS+CA-12345678", extendedInformation.getCabfOrganizationIdentifier());
        assertEquals("Wrong scheme identifier was extracted.", "NTR", extendedInformation.getCabfRegistrationSchemeIdentifier());
        assertEquals("Wrong country code was extracted.", "US", extendedInformation.getCabfRegistrationCountry());
        assertEquals("Wrong state or province value was extracted", "CA", extendedInformation.getCabfRegistrationStateOrProvince());
        assertEquals("Wrong registration reference was extracted.", "12345678", extendedInformation.getCabfRegistrationReference());
    }
}
