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

package org.ejbca.core.model.approval;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.approval.approvalrequests.DummyApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 */
public class ApprovalRequestTest {
    
    private static byte[] testcertenc = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky"
            + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB"
            + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ"
            + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw"
            + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj"
            + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0"
            + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4"
            + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ"
            + "QUOBOvc=").getBytes());
    
    private static byte[] testcertenc2 = Base64.decode(("MIIDTTCCAjWgAwIBAgIIboZwZjMm33EwDQYJKoZIhvcNAQELBQAwNzEVMBMGA1UE"
            + "AwwMTWFuYWdlbWVudENBMREwDwYDVQQKDAhEZXYgQ0EgMTELMAkGA1UEBhMCU0Uw"
            + "HhcNMTUwNDE5MTk0OTUzWhcNMTcwNDE4MTk0OTUzWjAVMRMwEQYDVQQDDApTdXBl"
            + "ckFkbWluMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0TtZKgKBOwKW"
            + "SOOTxx0+zqhfzWz0LaUTVTaC06iaQ1w3x+wGSGxA/oF7n6zRdCsG85k/1NbQpO25"
            + "tQ3vtpqW2U1a0YB6yvTdEpApHofxjd9GV/JtKpKJqRPZEqv4pnG21GK6WeWxvAEc"
            + "RFsFi6ZO/yxVrB9e3LSUUhDA0kfQEaRf+x6toFT4w0mG8pDxQSWINBMZ/LVwvEA+"
            + "OCahG3a4KUREbgqIylFf6auv3HQ/k8kIvmbtzUu9v3ixfArvvZH6DnRleLINUB3t"
            + "NYXrEsLcfAkjzV9W+Nzgdjm34Xhvg8+aIvmbO3OaR7z3O1VXoXDaHHnTv3R7888U"
            + "edVD1jc0jwIDAQABo38wfTAdBgNVHQ4EFgQU7ZA2TWTXZfNUD8rnYmx6il2YDfUw"
            + "DAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTM2eQQAXey4PApuOauspuJcEKByTAO"
            + "BgNVHQ8BAf8EBAMCBeAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMEMA0G"
            + "CSqGSIb3DQEBCwUAA4IBAQBiA3r6bbuCKkI4cZtg/DlnX2pzj0jr8rhJYEvZLhGk"
            + "t0JSYwwuPQi9YVKS/X6+V5b3VzwviR6MtLHrBOkNd64sS3M5nGxSkwxn7S5IewkT"
            + "7DOml2uhCOuxOVK59mtHbb/HCcp99IUFq8otgie5gt0LWpmYUGeEbeRH0guNtBaJ"
            + "N2zA/jXNlPxhGNZg9LoVtd2DSTWQIwD6xojiaCC3ZeQaLMyoOZCvFWMnm8hMSWzX"
            + "eXB7cRIf/48RsyOYyoHNDo2Z5JsZMS0nqdkeLtFLyVGWHWmpSebA3qP3E8cZtDJS"
            + "d4Msz2fuxKqNDnxIRPcbjHbn0cOa/tmC1aN/MJ1QymRD").getBytes());
	
    @Test
	public void testWriteExternal() throws Exception {
		X509Certificate testcert = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken token = new X509CertificateAuthenticationToken(testcert);

        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("AccumulativeApprovalProfile");
        approvalProfile.initialize();
        approvalProfile.setNumberOfApprovalsRequired(2);
		DummyApprovalRequest ar = new DummyApprovalRequest(token, null, 1, 2, false, approvalProfile);
		
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	oos.writeObject(ar);
    	oos.flush();
    	String result = new String(Base64.encode(baos.toByteArray(),false));

    	
    	ApprovalRequest readrequest = getApprovalRequest(result);
    	assertTrue(readrequest.getApprovalType() == ApprovalDataVO.APPROVALTYPE_DUMMY);
    	assertTrue(readrequest.getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_SIMPLE);
    	assertTrue(readrequest.getRequestSignature() == null);
    	assertTrue(CertTools.getSerialNumber(readrequest.getRequestAdminCert()).equals(CertTools.getSerialNumber(testcert)));
    	assertTrue(readrequest.getCAId() == 1);
    	assertTrue(readrequest.getEndEntityProfileId() == 2);
    	assertTrue(readrequest.getApprovalProfile()!=null);
    	assertTrue(readrequest.getApprovalProfile().getProfileName().equals(approvalProfile.getProfileName()));
    	assertTrue(!readrequest.isExecutable());
		
	}
    
    private  ApprovalRequest getApprovalRequest(String data) throws IOException, ClassNotFoundException {
        ApprovalRequest retval = null; 
        ObjectInputStream ois = null;
        try {
            ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(data.getBytes())));
            retval= (ApprovalRequest) ois.readObject();
        }finally {
            if(ois != null) {
                ois.close();
            }
        }
        return retval;
    }

    @Test
	public void testGenerateApprovalId() throws Exception {
		X509Certificate testcert = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken token = new X509CertificateAuthenticationToken(testcert);

        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("AccumulativeApprovalProfile");
        approvalProfile.initialize();
        approvalProfile.setNumberOfApprovalsRequired(2);
        DummyApprovalRequest ar = new DummyApprovalRequest(token, null, 1, 2, false, approvalProfile);
		
    	int id1 = ar.generateApprovalId();
    	int id2 = ar.generateApprovalId();
    	assertEquals(id1, id2);
    	
        final String TEST_NONADMIN_USERNAME = "wsnonadmintest";
        final String TEST_NONADMIN_CN = "CN=wsnonadmintest";
        final String serialNumber = "12344711";
        approvalProfile.setNumberOfApprovalsRequired(1);
        ApprovalRequest approvalRequest = new ViewHardTokenDataApprovalRequest(TEST_NONADMIN_USERNAME, 
                TEST_NONADMIN_CN, serialNumber, true, token, null, 1, 0, 0, approvalProfile);
        int approvalId = approvalRequest.generateApprovalId();
        ViewHardTokenDataApprovalRequest ar1 = new ViewHardTokenDataApprovalRequest(TEST_NONADMIN_USERNAME, 
                CertTools.stringToBCDNString(TEST_NONADMIN_CN), serialNumber, true,token,null,1,123456,1, 
                approvalProfile);
        int approvalId1 = ar1.generateApprovalId();
        assertEquals("Ids should be the same.", approvalId, approvalId1);


	}
    
    /** Tests editing (but not actually saving to the database, since this is handled in the ApprovalSessionBean class) */
    @Test
    public void testEditedByMe() throws Exception {
        X509Certificate testcert = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken token = new X509CertificateAuthenticationToken(testcert);
        
        X509Certificate testcertDup = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken tokenDup = new X509CertificateAuthenticationToken(testcertDup);
        
        X509Certificate testcert2 = CertTools.getCertfromByteArray(testcertenc2, X509Certificate.class);
        AuthenticationToken token2 = new X509CertificateAuthenticationToken(testcert2);
        
        AuthenticationToken token3 = new PublicAccessAuthenticationToken("127.0.0.1", true);
        
        AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("AccumulativeApprovalProfile");
        approvalProfile.initialize();
        approvalProfile.setNumberOfApprovalsRequired(2);
        DummyApprovalRequest ar = new DummyApprovalRequest(token, null, 1, 2, false, approvalProfile);
        
        assertFalse("Fresh approval request should not say it has been edited.", ar.isEditedByMe(token));
        assertFalse(ar.isEditedByMe(tokenDup));
        assertFalse(ar.isEditedByMe(token2));
        assertFalse(ar.isEditedByMe(token3));
        
        ar.addEditedByAdmin(token);
        assertTrue(ar.isEditedByMe(token));
        assertTrue(ar.isEditedByMe(tokenDup));
        assertFalse(ar.isEditedByMe(token2));
        assertFalse(ar.isEditedByMe(token3));
        
        ar.addEditedByAdmin(token2);
        assertFalse(ar.isEditedByMe(token)); // no longer the last admin who edited it, so this admin may edit again
        assertFalse(ar.isEditedByMe(tokenDup));
        assertTrue(ar.isEditedByMe(token2));
        assertFalse(ar.isEditedByMe(token3));
    }

    @BeforeClass
	public static void beforeClass() throws Exception {		
		CryptoProviderTools.installBCProviderIfNotAvailable();
	}

}
