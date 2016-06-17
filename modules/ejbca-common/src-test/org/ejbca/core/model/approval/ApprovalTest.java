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
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Test to externalize an approval
 * 
 * $Id$
 */

public class ApprovalTest {
    
    private static final Logger log = Logger.getLogger(ApprovalTest.class);
	
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

    @SuppressWarnings("deprecation")
    @Test
	public void testWriteExternal() throws Exception {
		ArrayList<Approval> approvals = new ArrayList<Approval>();	
		int sequenceIdentifier = 4711;
		int partitionIdentifier = 1337;
		Approval ap = new Approval("test", sequenceIdentifier, partitionIdentifier);
		Date apDate = ap.getApprovalDate();
		
		X509Certificate testcert = CertTools.getCertfromByteArray(testcertenc, X509Certificate.class);
        AuthenticationToken token = new X509CertificateAuthenticationToken(testcert);
		ap.setApprovalAdmin(true, token);
		approvals.add(ap);
		
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	
		int size = approvals.size();
		oos.writeInt(size);
		for(Approval approval : approvals) {
			oos.writeObject(approval);
		}
		oos.flush();
    	String result = new String(Base64.encode(baos.toByteArray(),false));

    	Collection<Approval> readapprovals = getApprovals(result);
    	assertTrue(readapprovals.size() == 1);
    	
    	Approval rap = readapprovals.iterator().next();
    	X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken)rap.getAdmin(); 
    	assertEquals(CertTools.getIssuerDN(testcert), CertTools.getIssuerDN(xtok.getCertificate()));
    	assertEquals(CertTools.getSerialNumber(testcert), CertTools.getSerialNumber(xtok.getCertificate()));
    	assertEquals(CertTools.getIssuerDN(testcert), rap.getAdminCertIssuerDN());
    	assertEquals(CertTools.getSerialNumber(testcert), rap.getAdminCertSerialNumber());
    	assertTrue(rap.isApproved());
    	assertEquals("test", rap.getComment());
    	assertEquals(apDate, rap.getApprovalDate());
    	assertEquals("Sequence identifier was not externalized successfully", sequenceIdentifier, rap.getStepId());
    	
	}
    
    private static Collection<Approval> getApprovals(String stringdata) {
        ArrayList<Approval> retval = new ArrayList<Approval>();
        try{
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decode(stringdata.getBytes())));
            int size = ois.readInt();
            for(int i=0;i<size;i++){
                Approval next = (Approval) ois.readObject();
                retval.add(next);
            }
        } catch (IOException e) {
            log.error("Error building approvals.",e);
            throw new EJBException(e);
        } catch (ClassNotFoundException e) {
            log.error("Error building approvals.",e);
            throw new EJBException(e);
        }
        return retval;
    }

}
