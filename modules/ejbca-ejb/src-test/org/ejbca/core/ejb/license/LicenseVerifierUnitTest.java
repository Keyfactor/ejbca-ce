/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.license;

import static org.junit.Assert.assertEquals;

import org.cesecore.license.LicenseState;
import org.cesecore.license.LicenseStateContainer;
import org.ejbca.core.EjbcaException;
import org.junit.Test;

import jakarta.xml.bind.JAXBException;

public class LicenseVerifierUnitTest {
    
    private static final String EXPIRED_LICENSE = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LicenseData><License id=\"c7f1f3f7-7dde-462c-bfaa-cee5176474fa\" issuedDate=\"2023-11-14 00:00:00Z\" expirationDate=\"2023-11-14 00:00:00Z\" issuerName=\"KEYFACTOR\\plasak\" /><Customer name=\"expired time 1cert EJBCA\" crm_id=\"3\" /><Products><Product id=\"93836326-5405-4e66-a0f7-ac7d6fc9f8ab\" displayName=\"EJBCA LRA Appliance\" majorRev=\"1\" minorRev=\"0\"><Features><Feature id=\"coreFunctionality\" displayName=\"EJBCA LRA Core Functionality\" enabled=\"True\" /><Feature id=\"active_cert_count\" displayName=\"Active Certificate Count\" enabled=\"True\" quantity=\"1\" /></Features></Product></Products><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>zy74umtZrh3lH1PzVr0AVUdZxpFWQRWpX6GNyXYr6ao=</DigestValue></Reference></SignedInfo><SignatureValue>wPX4w3x3XnrcgyQCnLJDuc9dBYK4S6PRZoDnPPBwljk8km41++LP5ga0aMxfTk7XBmMhVAlCVabGgy1fl+zyvSZoX+fOfXRdZ7NegrrnZmPcCMiZdMNzr31tmRsIggzbOXDsVniONTm4rSfLFH+/SZywNoDCVFrVQi472mO4aLEPjTw7w0liQNW2kbX3Kf0Ok5chiqy+S4y2ekNztR3WqUHORFpIQgfKXLqUF4ogDxdaNmYzisNHK1XWeuSE7+cYWdfw1Y2LMQfyQPUyYF28mbv6/yRT7gXbMSyQghGRmMU/u+Ay5LF5JquneD/RVZQewePiFK8Oy/cKh+Gkp8D8ww==</SignatureValue></Signature></LicenseData>";

    private static final String INVALID_LICENSE = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LicenseData><License id=\"ea074062-1ad0-42df-81d3-adf941ebb072\" issuedDate=\"2023-10-27 00:00:00Z\" issuerName=\"KEYFACTOR\\plasak\" /><Customer name=\"Benny GmbH\" crm_id=\"1\" /><Products><Product id=\"dffbe627-bf38-418c-b21a-3004374adf3c\" displayName=\"EJBCA Appliance\" majorRev=\"1\" minorRev=\"0\"><Features><Feature id=\"coreFunctionality\" displayName=\"EJBCA Core Functionality\" enabled=\"True\" /><Feature id=\"active_cert_count\" displayName=\"Active Certificate Count\" enabled=\"True\" quantity=\"2500\" /></Features></Product></Products><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><DigestValue>hh+nvjGbbu8q8JLrUrCFKB+0uI8=</DigestValue></Reference></SignedInfo><SignatureValue>rJriDf4zCamW/0Y24DdsgXYRHAM3CyPWi+zzDx0RXNrY+2i4bhrpNoFIE4pMt06J3Cjf5iU/Uu9XoweuZDXRKXfTmPqcg4lNc5mT4XlYh6Z1mjV/sDQkrrOSdAYdcU5nXGzF8YVlhwOBvsFArC6EVTsrekbtVR74AXIXzACLSKWAh/ydy3UBjlDtrLGp5fw3DXgqrgsNow/w1mlOn3Rvv9Nd559PrPVwBlkqJQDGUlYsz+2pyiJm/UuAenRarHylIY+G1/iNlNLbp2CJpRmAc5hxjAb/a7g1aicnOQfgDZpxvzxMSVooeAVsNaYVuoYWyHROVmVe1UCu6dFv5x3jKQ==</SignatureValue></Signature></LicenseData>";

    private static final String INVALID_XML_LICENSE = "<?xml version=\"2.0\" encoding=\"utf-8\"?><LicenseData><License id=\"c7f1f3f7-7dde-462c-bfaa-cee5176474fa\" issuedDate=\"2023-11-14 00:00:00Z\" expirationDate=\"2040-11-14 00:00:00Z\" issuerName=\"KEYFACTOR\\plasak\" /><Customer name=\"unlimited time 1cert EJBCA\" crm_id=\"3\" /><Products><Product id=\"93836326-5405-4e66-a0f7-ac7d6fc9f8ab\" displayName=\"EJBCA LRA Appliance\" majorRev=\"1\" minorRev=\"0\"><Features><Feature id=\"coreFunctionality\" displayName=\"EJBCA LRA Core Functionality\" enabled=\"True\" /><Feature id=\"active_cert_count\" displayName=\"Active Certificate Count\" enabled=\"True\" quantity=\"1\" /></Features></Product></Products><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>fh6lI2fAbJFulA3NhDNLYuHmsdrvFP5r5m3bpU3yaqk=</DigestValue></Reference></SignedInfo><SignatureValue>yKZkZMkFOevBY6tB3v4ynrJc6FmcDXcIFpqXwtlrYzSq742M4w6bEHYIwUWx0aaTF4ca5Z9ud9tq9GNfASDuxF1olVHYIQe7UEg6VVGUHFU1ukEmfflRQdCqudJPjdq7rrodzvw072RaxNA8ZalZVifnPIq0Oi4efpZ9X77bQuvUHPLOmrKbpdSXhoImm0C1/dXAxu55LY4vZHbxwtKttyfQ2W9Jcp+DU5t9NFDA69BJAN7sves07EXiRcRkzOV2mq3zF5WGrNEifKjODUNHfQIwnumw1gkOsOLz2r5r88RHZIGzN17NMDWcTUuL8o1eOLDZMAcaiNYDUSG2lW5hKA==</SignatureValue></Signature></LicenseData>";
    
    private static final String OTHER_PRODUCT_LICENSE = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LicenseData><License id=\"16cf8b07-7816-4914-ae56-892011bbfa3f\" issuedDate=\"2023-11-14 00:00:00Z\" expirationDate=\"2040-11-14 00:00:00Z\" issuerName=\"KEYFACTOR\\plasak\" /><Customer name=\"unlimited time SS\" crm_id=\"3\" /><Products><Product id=\"5c0e734c-5bbc-435f-9f12-0452d32235d1\" displayName=\"SignServer Appliance\" majorRev=\"1\" minorRev=\"0\"><Features><Feature id=\"coreFunctionality\" displayName=\"SignServer Core Functionality\" enabled=\"True\" /></Features></Product></Products><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>mjUIvCPb80N4xdkpGxmuu4ZO3sMB8w+jj/IqLV0oXSI=</DigestValue></Reference></SignedInfo><SignatureValue>WtomN86rU0ta7HVhSv1axGhIwKVM9xf1wZSlKfDxozvZXLjz9u0QhUbvCgx+3kQoar2+eInQ0z1d4vvaZamN4OwRYpskptQ+RBTCYf11Ln0PXkOE5XVwqb0rzxkR4bbbPuyxqkRHYX19RNeGFaxuvBHwJ45KW2TlouqcPqCn/5+pm0ivZ5vHM5ldKFqtx5QLTsu8hy6mN0MnoDCr4+Df3tcXAaoW8LzBYufLySdObRHSenw0H5E8tH4wcWtm7zKjHMyJaRN0nxaYVFJf+9gaT2nhx9ZEmAqRzfg75ZLp+HhGOqKZMtBFrzKR+8AlWuCzBnbTQzLNblPrLFxmTczGbA==</SignatureValue></Signature></LicenseData>";
    
    private static final String VALID_LICENSE = "<?xml version=\"1.0\" encoding=\"utf-8\"?><LicenseData><License id=\"fe6ef061-87ae-43b9-aa60-d477a405bc3d\" issuedDate=\"2023-11-15 00:00:00Z\" expirationDate=\"2040-11-15 00:00:00Z\" issuerName=\"KEYFACTOR\\plasak\" /><Customer name=\"unmilited time 1cert EJBCA\" crm_id=\"3\" /><Products><Product id=\"dffbe627-bf38-418c-b21a-3004374adf3c\" displayName=\"EJBCA Appliance\" majorRev=\"1\" minorRev=\"0\"><Features><Feature id=\"coreFunctionality\" displayName=\"EJBCA Core Functionality\" enabled=\"True\" /><Feature id=\"active_cert_count\" displayName=\"Active Certificate Count\" enabled=\"True\" quantity=\"1\" /></Features></Product></Products><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>VhfPjc/ApXuTevNN0eCyDlRw4Wib/jae5zyzcXo0ues=</DigestValue></Reference></SignedInfo><SignatureValue>rke/9xm5oITNwrySyADkuiQHwMYjKGCwcA/Yx9wxIA3jYdACimXfOzY4hMpC9AcOAIvKqpEXqvCd+g99EpdmTpmYg8lefhBtInc/wWdGjXcV5Es9VVbihgvOGexu7JgpXsw1b8Qzb8bJZOZif+hT73KUOzatjeJrKEXSoYaHnWZRlfjeyGQ+FonVKbzehlYyOfOE/My0fxX3dNLb5H3DBsbB5ZWGjBwem5Oc2fvOkIhdQhr2Zm8mxNvQ56m61J7tmu+EwyuqUgeJ2cyKo1ArpjRdjfRuDhXrbcYoNyWO9Wyf+C/qR6b6S7BXD1F6GDYgwhZoARNCldLeDhTipb9Zug==</SignatureValue></Signature></LicenseData>";
    
    @Test
    public void test() throws EjbcaException, JAXBException {
        new LicenseVerifierEnterpriseSessionBean().validateLicense(VALID_LICENSE);
        assertEquals(LicenseStateContainer.getLicenseState(), LicenseState.VALID);
    }
    
    @Test
    public void test2() throws EjbcaException, JAXBException {
        new LicenseVerifierEnterpriseSessionBean().validateLicense(INVALID_LICENSE);
        assertEquals(LicenseStateContainer.getLicenseState(), LicenseState.INVALID);
    }
    
    @Test
    public void test3() throws EjbcaException, JAXBException {
        new LicenseVerifierEnterpriseSessionBean().validateLicense(OTHER_PRODUCT_LICENSE);
        assertEquals(LicenseStateContainer.getLicenseState(), LicenseState.INVALID);
    }
    
    @Test
    public void test4() throws EjbcaException, JAXBException {
        new LicenseVerifierEnterpriseSessionBean().validateLicense(INVALID_XML_LICENSE);
        assertEquals(LicenseStateContainer.getLicenseState(), LicenseState.INVALID);
    }
    
    @Test
    public void test5() throws EjbcaException, JAXBException {
        new LicenseVerifierEnterpriseSessionBean().validateLicense(EXPIRED_LICENSE);
        assertEquals(LicenseStateContainer.getLicenseState(), LicenseState.EXPIRED_LONG_BACK);
    }

}
