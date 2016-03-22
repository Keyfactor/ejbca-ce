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

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test to externalize an approval
 * @author Philip Vendil
 * $Id$
 */

public class ApprovalTest {
	
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

    @BeforeClass
	public static void beforeClass() throws Exception {
		CryptoProviderTools.installBCProvider();
	}

    @Test
	public void testWriteExternal() throws Exception {
		ArrayList<Approval> approvals = new ArrayList<Approval>();		
		Approval ap = new Approval("test");
		Date apDate = ap.getApprovalDate();
		
		X509Certificate testcert = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken token = new X509CertificateAuthenticationToken(testcert);
		ap.setApprovalAdmin(true, token);
		approvals.add(ap);
		
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	
		int size = approvals.size();
		oos.writeInt(size);
		Iterator<Approval> iter = approvals.iterator();
		while(iter.hasNext()){
			oos.writeObject(iter.next());
		}
		oos.flush();
    	String result = new String(Base64.encode(baos.toByteArray(),false));

    	Collection<Approval> readapprovals = ApprovalDataUtil.getApprovals(result);
    	assertTrue(readapprovals.size() == 1);
    	
    	Approval rap = readapprovals.iterator().next();
    	X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken)rap.getAdmin(); 
    	assertTrue(CertTools.getIssuerDN(xtok.getCertificate()).equals(CertTools.getIssuerDN(testcert)));
    	assertTrue(CertTools.getSerialNumber(xtok.getCertificate()).equals(CertTools.getSerialNumber(testcert)));
    	assertTrue(rap.getAdminCertIssuerDN().equals(CertTools.getIssuerDN(testcert)));
    	assertTrue(rap.getAdminCertSerialNumber().equals(CertTools.getSerialNumber(testcert)));
    	//assertTrue(rap.getAdmin().getUsername().equals("USERNAME"));
    	assertTrue(rap.isApproved());
    	assertTrue(rap.getComment().equals("test"));
    	assertTrue(rap.getApprovalDate().equals(apDate));
	}

}
