/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util.msae;

import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.protocol.msae.KeyArchivalException;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Cache holding CA id and associated kec (key exchange certificate) 
 */
public enum KECCache {
    INSTANCE;

    private static final Logger log = Logger.getLogger(KECCache.class);

    private static final ConcurrentMap<Integer, Certificate> KEC_CACHE = new ConcurrentHashMap<>();

    public Certificate getCachedKEC(final AuthenticationToken admin, final int cAId, final int cPId)
            throws CertificateEncodingException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException, OperatorCreationException, IllegalNameException,
            AuthorizationDeniedException, CertificateExtensionException, KeyArchivalException {

        Certificate kec = KEC_CACHE.get(cAId);

        if (Objects.isNull(kec)) {
            return generateKecOnCaSideAndCache(admin, cAId, cPId);
        } else {
            try {
                ((X509Certificate) kec).checkValidity();
                log.debug("Found a valid kec in cache, returning it!");
                return kec;
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                log.debug("The cached kec is expired, requesting a new one from ca side.");
                return generateKecOnCaSideAndCache(admin, cAId, cPId);
            }
        }
    }

    public static void clearCache() {
        KECCache.KEC_CACHE.clear();
        log.info("KEC cache cleared.");
    }

    private Certificate generateKecOnCaSideAndCache(final AuthenticationToken admin, final int cAId, final int cPId)
            throws AuthorizationDeniedException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CertificateExtensionException, CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException,
            OperatorCreationException, IllegalNameException, CertificateEncodingException, KeyArchivalException {
        Certificate kec;
        kec = new EjbLocalHelper().getRaMasterApiProxyBean().getKeyExchangeCertificate(admin, cAId, cPId);
        if (Objects.isNull(kec)) {
            log.debug("RaMasterApi returns null instead of key exchange certificate.");
            throw new KeyArchivalException("Null key exchange certificate returned by the CA!");
        } else {
            KEC_CACHE.put(cAId, kec);
        }
        return kec;
    }
}
