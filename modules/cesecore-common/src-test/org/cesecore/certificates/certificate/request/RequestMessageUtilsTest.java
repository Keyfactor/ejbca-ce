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
package org.cesecore.certificates.certificate.request;

import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CryptoProviderTools;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Testing parsing request messages with RequestMessageUtils
 */
public class RequestMessageUtilsTest {

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testParseRequestMessage() {
        RequestMessage msg = RequestMessageUtils.parseRequestMessage(p10utf8StringPwd);
        assertEquals("RequestMessage (from DER) should be a PKCS10RequestMessage", PKCS10RequestMessage.class.getName(), msg.getClass().getName());
        msg = RequestMessageUtils.parseRequestMessage(p10utf8StringPwdPEM.getBytes());
        assertEquals("RequestMessage (from PEM) should be a PKCS10RequestMessage", PKCS10RequestMessage.class.getName(), msg.getClass().getName());
        msg = RequestMessageUtils.parseRequestMessage(cvcEac111IS);
        assertEquals("RequestMessage (from DER) should be a CVCRequestMessage", CVCRequestMessage.class.getName(), msg.getClass().getName());
        msg = RequestMessageUtils.parseRequestMessage(cvcEac111ISPEM.getBytes());
        assertEquals("RequestMessage (from PEM) should be a CVCRequestMessage", CVCRequestMessage.class.getName(), msg.getClass().getName());
        msg = RequestMessageUtils.parseRequestMessage(brokenCVC);
        assertNull("Unparseable request should return null", msg);
        msg = RequestMessageUtils.parseRequestMessage(undecodablePEM.getBytes());
        assertNull("Un-decodeable request should return null", msg);

    }

    /** a P10 with a PKCS#9 challengePassword encoded as UTF8String, DER (binary) format */
    private static byte[] p10utf8StringPwd = Base64.decode(("MIIBITCBzAIBADBHMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTER"+
            "MA8GA1UECgwIUHJpbWVLZXkxEDAOBgNVBAMMB3AxMHRlc3QwXDANBgkqhkiG9w0B"+
            "AQEFAANLADBIAkEArE7GcTm9U3rEqTfldN+Ja3FnMhZXfq3Uq4AWi2VPVqEDmJzX"+
            "TINOlnDeK3y4jJ1kNqrSITfznobbDHR1pNSWYwIDAQABoCAwHgYJKoZIhvcNAQkH"+
            "MREMD2ZTUkVwOHBueHR4M0N1VjANBgkqhkiG9w0BAQsFAANBAGO8WZj42s3lo463"+
            "SdaP7kqE15BdkbReCIV+HA8dw9dphulLyFTTAxGZs8c28O2f81iA9jtW8yLUWnSg"+
            "UaIHwek=").getBytes());

    /** a P10 with a PKCS#9 challengePassword encoded as UTF8String, PEM format */
    private static String p10utf8StringPwdPEM = "-----BEGIN CERTIFICATE REQUEST-----\n"+
            "MIIBITCBzAIBADBHMQswCQYDVQQGEwJTRTETMBEGA1UECAwKU29tZS1TdGF0ZTER\n"+
            "MA8GA1UECgwIUHJpbWVLZXkxEDAOBgNVBAMMB3AxMHRlc3QwXDANBgkqhkiG9w0B\n"+
            "AQEFAANLADBIAkEArE7GcTm9U3rEqTfldN+Ja3FnMhZXfq3Uq4AWi2VPVqEDmJzX\n"+
            "TINOlnDeK3y4jJ1kNqrSITfznobbDHR1pNSWYwIDAQABoCAwHgYJKoZIhvcNAQkH\n"+
            "MREMD2ZTUkVwOHBueHR4M0N1VjANBgkqhkiG9w0BAQsFAANBAGO8WZj42s3lo463\n"+
            "SdaP7kqE15BdkbReCIV+HA8dw9dphulLyFTTAxGZs8c28O2f81iA9jtW8yLUWnSg\n"+
            "UaIHwek=\n"+
            "-----END CERTIFICATE REQUEST-----";

    /** a CVC EAC 1.11 request from an IS, DER (binary) format */
    private static byte[] cvcEac111IS = Base64.decode(("fyGCAX5/ToIBNl8pAQB/SYIBHQYKBAB/AAcCAgICA4Eg/////wAAAAEAAAAAAAAA" + 
            "AAAAAAD///////////////+CIP////8AAAABAAAAAAAAAAAAAAAA////////////" + 
            "///8gyBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgS4RBBGsX0fLhLEJH" + 
            "+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7O" + 
            "y7ZAaDe/UfWFIP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRhkEE1w7E" + 
            "Zzwd3xi+uqPfKaUKlvjugx0bX6gcp8YIoFMquLk+Cy4dat9fs3D5TM+zGzm+quKP" + 
            "HtqISYD72coDzZq/RIcBAV8gDVNFSVNTRUNQMDAwMDFfN0C+EQysfY036CLPJZZo" + 
            "c72tc80pFjWF00vGt9T1OPHFMDkUNTBwreRnQ1JM8Src4H6B3+ZLKDd3nIkFCWFN" + 
            "hbjj").getBytes());

    /** a CVC EAC 1.11 request from an IS, PEM format */
    private static String cvcEac111ISPEM = "-----BEGIN CERTIFICATE REQUEST-----\n"+
            "fyGCAX5/ToIBNl8pAQB/SYIBHQYKBAB/AAcCAgICA4Eg/////wAAAAEAAAAAAAAA\n" + 
            "AAAAAAD///////////////+CIP////8AAAABAAAAAAAAAAAAAAAA////////////\n" + 
            "///8gyBaxjXYqjqT57PrvVV2mIa8ZR0GsMxTsPY7zjw+J9JgS4RBBGsX0fLhLEJH\n" + 
            "+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7O\n" + 
            "y7ZAaDe/UfWFIP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRhkEE1w7E\n" + 
            "Zzwd3xi+uqPfKaUKlvjugx0bX6gcp8YIoFMquLk+Cy4dat9fs3D5TM+zGzm+quKP\n" + 
            "HtqISYD72coDzZq/RIcBAV8gDVNFSVNTRUNQMDAwMDFfN0C+EQysfY036CLPJZZo\n" + 
            "c72tc80pFjWF00vGt9T1OPHFMDkUNTBwreRnQ1JM8Src4H6B3+ZLKDd3nIkFCWFN\n" + 
            "hbjj\n"+
            "-----END CERTIFICATE REQUEST-----";

    /** a broken CVC request that will not be able to be parsed */
    private static byte[] brokenCVC = Base64.decode(("GCAX").getBytes());

    /** a broken PEM request that will not be able to be Base64 decoded */
    private static String undecodablePEM = "-----BEGIN CERTIFICATE REQUEST-----\n"+
            "fyGCAX\n"+
            "-----END CERTIFICATE REQUEST-----";

}
