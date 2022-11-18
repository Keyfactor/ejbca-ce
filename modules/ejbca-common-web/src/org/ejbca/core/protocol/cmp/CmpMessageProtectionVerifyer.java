package org.ejbca.core.protocol.cmp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.cmp.CMPException;

/**
 * Interface for verifiers of CMP protection.
 * Currently implemented by {@link CmpPbeVerifyer} and {@link CmpPbmac1Verifyer}
 */
public interface CmpMessageProtectionVerifyer {
   boolean verify(final String password) throws InvalidKeyException, NoSuchAlgorithmException, CMPException;
   String getErrMsg();
   ASN1ObjectIdentifier getProtectionAlg();
}
