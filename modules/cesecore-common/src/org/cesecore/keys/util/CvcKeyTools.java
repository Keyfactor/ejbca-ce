/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.util;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;

import org.apache.log4j.Logger;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.ejbca.cvc.PublicKeyEC;

/**
 * Utility class for CVC-key related methods
 *
 */
public class CvcKeyTools {

    
    private static final Logger log = Logger.getLogger(CvcKeyTools.class);

    
    private CvcKeyTools() {
        
    }
    
    /**
     * An ECDSA key can be stripped of the curve parameters so it only contains the public point, and this is not enough to use the key for
     * verification. However, if we know the curve name we can fill in the curve parameters and get a usable EC public key
     * 
     * @param pk
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that might miss parameters, if parameters are there we do not touch the public key just return it unchanged
     * @param keySpec
     *            name of curve for example brainpoolp224r1
     * @return PublicKey with parameters from the named curve
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PublicKey getECPublicKeyWithParams(final PublicKey pk, final String keySpec) throws NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        PublicKey ret = pk;
        if ((pk instanceof PublicKeyEC) && (keySpec != null)) {
            final PublicKeyEC pkec = (PublicKeyEC) pk;
            // The public key of IS and DV certificate do not have any parameters so we have to do some magic to get a complete EC public key
            final ECParameterSpec spec = pkec.getParams();
            if (spec == null) {
                // we did not have the parameter specs, lets create them because we know which curve we are using
                final org.bouncycastle.jce.spec.ECParameterSpec bcspec = ECNamedCurveTable.getParameterSpec(keySpec);
                final java.security.spec.ECPoint p = pkec.getW();
                final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(bcspec.getCurve(), p);
                final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
                final KeyFactory keyfact = KeyFactory.getInstance("ECDSA", "BC");
                ret = keyfact.generatePublic(pubKey);
            }
        }
        return ret;
    }
    
    /**
     * An ECDSA key can be stripped of the curve parameters so it only contains the public point, and this is not enough to use the key for
     * verification. However, if we know the curve name we can fill in the curve parameters and get a usable EC public key
     * 
     * @param pk
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that might miss parameters, if parameters are there we do not touch the public key just return it unchanged
     * @param pkwithparams
     *            PublicKey, org.ejbca.cvc.PublicKeyEC, that contains all parameters.
     * @return PublicKey with parameters from the named curve
     *
     * @throws InvalidKeySpecException if the key specification in pkwithparams was invalid
     */
    public static PublicKey getECPublicKeyWithParams(final PublicKey pk, final PublicKey pkwithparams) throws InvalidKeySpecException {
        if ( !(pk instanceof PublicKeyEC) || !(pkwithparams instanceof PublicKeyEC) ) {
            log.info("Either pk or pkwithparams is not a PublicKeyEC: " + pk.toString() + ", " + pkwithparams.toString());
            return pk;
        }
        final PublicKeyEC pkec = (PublicKeyEC) pk;
        final ECParameterSpec spec = pkec.getParams();
        if (spec != null) {
            return pk;// the key already has its parameters.
        }
        // The public key of IS and DV certificate do not have any parameters so we have to do some magic to get a complete EC public key
        final PublicKeyEC pkecp = (PublicKeyEC) pkwithparams;
        final ECParameterSpec pkspec = pkecp.getParams();
        if (pkspec == null) {
            log.info("pkwithparams does not have any params.");
            return pk;
        }
        final org.bouncycastle.jce.spec.ECParameterSpec bcspec = EC5Util.convertSpec(pkspec);
        final java.security.spec.ECPoint p = pkec.getW();
        final org.bouncycastle.math.ec.ECPoint ecp = EC5Util.convertPoint(pkspec, p);
        final ECPublicKeySpec pubKey = new ECPublicKeySpec(ecp, bcspec);
        final KeyFactory keyfact;
        try {
            keyfact = KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("ECDSA was an unknown algorithm", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle was not found as a provider.", e);
        }
        return keyfact.generatePublic(pubKey);
    }

}
