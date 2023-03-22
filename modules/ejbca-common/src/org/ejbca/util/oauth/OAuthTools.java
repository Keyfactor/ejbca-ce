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
package org.ejbca.util.oauth;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;

import org.apache.log4j.Logger;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;

/**
 * Class containing static helper methods for OAuth operations
 */
public class OAuthTools {

    private static final Logger log = Logger.getLogger(KeyTools.class);

    /** Like {@link KeyTools.getBytesFromPublicKeyFile}, but allows certificates and JWK keys also <code>{"kid":</code>... */
    public static byte[] getBytesFromOauthKey(final byte[] bytes) throws CertificateParsingException {
        try {
            return KeyTools.getBytesFromPublicKeyFile(bytes);
        } catch (CertificateParsingException originalException) {
            if (bytes.length == 0) {
                throw originalException; // No point in parsing empty files as cert or JWK
            }
            log.debug("Could not parse key as PEM or DER, trying to parse as certificate.");
            try {
                final X509Certificate cert = CertTools.getCertfromByteArray(bytes, X509Certificate.class);
                final PublicKey publicKey = cert.getPublicKey();
                return publicKey.getEncoded();
            } catch (CertificateParsingException certException) {
                log.debug("Could not parse key as PEM, DER or certificate, trying to parse as JWK.");
                try {
                    final JWK jwk = JWK.parse(new String(bytes, StandardCharsets.US_ASCII));
                    if (jwk instanceof AsymmetricJWK) {
                        return ((AsymmetricJWK) jwk).toPublicKey().getEncoded();
                    } else {
                        throw new CertificateParsingException("Wrong type of JWK key. Expected asymmetric key (EC or RSA), got unsupported key type "
                                + jwk.getKeyType().toString());
                    }
                } catch (ParseException | JOSEException | RuntimeException jwkException) {
                    log.debug("Failed to parse key as PEM, DER, X.509 certificate or JWK. Exception stack traces follow.");
                    log.debug("PEM/DER public key parsing exception", originalException);
                    log.debug("PEM/DER certificate parsing exception", certException);
                    log.debug("JWK parsing exception", jwkException);
                    throw new CertificateParsingException("Key could neither be parsed as PEM, DER, certificate or JWK", originalException);
                }
            }
        }
    }

    /**
     * Extracts the Key ID from JWK key.
     * @param bytes Encoded public key. Do <em>not</em> use the return value from getBytesFromOauthKey, that is always in DER format.
     * @return Key ID as a string, or null on any error (e.g. non JWK key)
     */
    public static String getKeyIdFromJwkKey(final byte[] bytes) {
        try {
            final JWK jwk = JWK.parse(new String(bytes, StandardCharsets.US_ASCII));
            final String keyId = jwk.getKeyID();
            if (log.isDebugEnabled()) {
                log.debug("Extracted JWK Key ID: " + keyId);
            }
            return keyId;
        } catch (RuntimeException | ParseException e) {
            if (log.isDebugEnabled()) {
                log.debug("Not a JWK key, ignoring: " + e.getMessage(), e);
            }
            return null;
        }
    }

}
