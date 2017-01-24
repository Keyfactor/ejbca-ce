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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;

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
        LinkedHashMap<String,Object> map = new LinkedHashMap<String,Object>();
        map.put(UpgradeableDataHashMap.VERSION, new Float(4));
        map.put("CERTIFICATE_REQUEST", Base64.decode(pkcs10.getBytes(StandardCharsets.UTF_8)));
        ei4.setData(map);
        assertEquals(pkcs10, new String(Base64.encode(ei4.getCertificateRequest()), StandardCharsets.UTF_8));
    }
    
}
