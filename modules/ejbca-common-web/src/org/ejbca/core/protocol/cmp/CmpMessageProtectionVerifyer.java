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
   /**
    * Verifies the underlying CMP message using the provided password.
    * @param password
    * @return true if it was possible to successfully verify the message protection with the provided password
    * @throws CMPException something failed during the validation of the PBMAC1 protection, caused by invalid parameters
	 * @throws InvalidKeyException if the key was not compatible with this MAC
	 * @throws NoSuchAlgorithmException if the algorithm for the Owf or the MAC weren't found
    */
   boolean verify(final String password) throws InvalidKeyException, NoSuchAlgorithmException, CMPException;

   /**
    * Method used to retrieve an error message with information about why the verification failed.
    * @return String error message
    */

   String getErrMsg();

   /**
    * Returns the object identifier of the protection type the verifyer is used for.
    * @return For example passwordBasedMac or PBMAC1 object identifier
    */
   ASN1ObjectIdentifier getProtectionAlg();
}
