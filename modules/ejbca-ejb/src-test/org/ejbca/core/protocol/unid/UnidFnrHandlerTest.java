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

package org.ejbca.core.protocol.unid;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.ejbca.core.ejb.unidfnr.UnidfnrSessionLocal;
import org.ejbca.core.protocol.cmp.ICrmfRequestMessage;
import org.junit.Test;

import com.keyfactor.util.CeSecoreNameStyle;

/**
 * Testing of {@link UnidFnrHandler} .
 */
public class UnidFnrHandlerTest {
	
   
    /**
     * Tests basic conversion between Fnr and UnID using a mock session bean to retrieve the data.
     */
    @Test
    public void testFnrHandler() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        final String unidPrefix = "1234-5678-";
        final String fnr = "90123456789";
        final String lra = "01234";
        final RequestMessage reqIn = new MyIRequestMessage(fnr + '-' + lra);
        final UnidfnrSessionLocal unidfnrSession = new UnidfnrSessionMock();
        final UnidFnrHandler handler = new UnidFnrHandler();
        //Insert the mock session bean into the UnidFnrHandler
        final Field unidfnrSessionField = UnidFnrHandler.class.getDeclaredField("unidfnrSession");
        unidfnrSessionField.setAccessible(true);
        unidfnrSessionField.set(handler, unidfnrSession);
        final RequestMessage reqOut = handler.processRequestMessage(reqIn, unidPrefix + "_a_profile_name");
        //The result should consist of the prefix + lra + six random characters
        String serialNumber = reqOut.getRequestX500Name().getRDNs(CeSecoreNameStyle.SERIALNUMBER)[0].getFirst().getValue().toString();
        assertEquals("Serial number is malformed, missing prefix sequence.", unidPrefix, serialNumber.subSequence(0, unidPrefix.length()));
        assertEquals("Serial number is malformed, missing LRA sequence.", lra,
                serialNumber.subSequence(unidPrefix.length(), lra.length() + unidPrefix.length()));
        assertEquals("FNR was not stored correctly.", fnr, unidfnrSession.fetchUnidFnrData(serialNumber));
    }
    
    /*
     * Mock class to simulate the existence of a session bean 
     */
    private static class UnidfnrSessionMock implements UnidfnrSessionLocal {
        private Map<String, String> storage = new HashMap<>();
        
        @Override
        public void storeUnidFnrData(String unid, String fnr) {
            storage.put(unid, fnr);
        }

        @Override
        public String fetchUnidFnrData(String serialNumber) {
            return storage.get(serialNumber);
        }

        @Override
        public void removeUnidFnrDataIfPresent(String unid) {
            storage.remove(unid);
        }
        
    }
    
	private static class MyIRequestMessage implements ICrmfRequestMessage {
		private static final long serialVersionUID = -2303591921932083436L;
        final X500Name dn;
        List<Certificate> additionalCaCertificates = new ArrayList<>();
        List<Certificate> additionalExtraCertsCertificates = new ArrayList<>();
        
		MyIRequestMessage(String serialNumber) {
		    X500NameBuilder nameBuilder = new X500NameBuilder(new CeSecoreNameStyle());
			nameBuilder.addRDN(CeSecoreNameStyle.SERIALNUMBER, serialNumber);
			this.dn = nameBuilder.build();
		}
		@Override
		public String getUsername() {
			return null;
		}
		@Override
		public String getPassword() {
			return null;
		}
		@Override
		public String getIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getSerialNo() {
			return null;
		}
	    @Override
	    public String getCASequence() {
	        return null;
	    }
		@Override
		public String getRequestDN() {
			return null;
		}
		@Override
		public X500Name getRequestX500Name() {
			return this.dn;
		}

		@Override
		public String getRequestAltNames() {
			return null;
		}
		@Override
		public Date getRequestValidityNotBefore() {
			return null;
		}
		@Override
		public Date getRequestValidityNotAfter() {
			return null;
		}
		@Override
		public Extensions getRequestExtensions() {
			return null;
		}
		@Override
		public String getCRLIssuerDN() {
			return null;
		}
		@Override
		public BigInteger getCRLSerialNo() {
			return null;
		}
		@Override
		public PublicKey getRequestPublicKey() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return null;
		}
		@Override
		public boolean verify() throws InvalidKeyException,
				NoSuchAlgorithmException, NoSuchProviderException {
			return false;
		}
		@Override
		public boolean requireKeyInfo() {
			return false;
		}
		@Override
		public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {
			// do nothing
		}
		@Override
		public int getErrorNo() {
			return 0;
		}
		@Override
		public String getErrorText() {
			return null;
		}
		@Override
		public String getSenderNonce() {
			return null;
		}
		@Override
		public String getTransactionId() {
			return null;
		}
		@Override
		public byte[] getRequestKeyInfo() {
			return null;
		}
		@Override
		public String getPreferredDigestAlg() {
			return null;
		}
		@Override
		public boolean includeCACert() {
			return false;
		}
		@Override
		public int getRequestType() {
			return 0;
		}
		@Override
		public int getRequestId() {
			return 0;
		}

	    @Override
	    public void setResponseKeyInfo(PrivateKey key, String provider) {
	    }

		@Override
		public int getPbeIterationCount() {
			return 0;
		}
		@Override
		public String getPbeDigestAlg() {
			return null;
		}
		@Override
		public String getPbeMacAlg() {
			return null;
		}
		@Override
		public String getPbeKeyId() {
			return null;
		}
		@Override
		public String getPbeKey() {
			return null;
		}
        @Override
        public boolean isImplicitConfirm() {
            return false;
        }
        @Override
        public PublicKey getProtocolEncrKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
            return null;
        }
        @Override
        public SubjectPublicKeyInfo getRequestSubjectPublicKeyInfo() {
            return null;
        }
        @Override
        public void setServerGenKeyPair(KeyPair serverGenKeyPair) {
        }
        @Override
        public KeyPair getServerGenKeyPair() {
            return null;
        }
        
        @Override
        public List<Certificate> getAdditionalCaCertificates() {
            return additionalCaCertificates;
        }
        @Override
        public void setAdditionalCaCertificates(final List<Certificate> certificates) {
            this.additionalCaCertificates = certificates;
        }
        @Override
        public List<Certificate> getAdditionalExtraCertsCertificates() {
            return this.additionalExtraCertsCertificates;
        }
        @Override
        public void setAdditionalExtraCertsCertificates(List<Certificate> certificates) {
            this.additionalExtraCertsCertificates = certificates;
        }
        @Override
        public void setUsername(String username) {
        }
        @Override
        public void setPassword(String pwd) {
        }
        @Override
        public void setRequestValidityNotAfter(Date notAfter) {
        }
	}
}
