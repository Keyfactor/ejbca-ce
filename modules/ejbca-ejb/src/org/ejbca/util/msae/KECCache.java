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

import javax.annotation.PostConstruct;
import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.ejb.EJB;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;

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
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.msae.KeyArchivalException;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Cache holding CA id and associated kec (key exchange certificate) 
 */
@Singleton
@Startup
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
@TransactionManagement(TransactionManagementType.BEAN)
public class KECCache {

    private static final Logger log = Logger.getLogger(KECCache.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    private ConcurrentMap<Integer, Certificate> currentKecCache;

    @PostConstruct
    public void init() {
        currentKecCache = new ConcurrentHashMap<>();
    }

    public KECCache() {
        //
    }

    public Certificate getCachedKEC(final AuthenticationToken admin, final int cAId, final int cPId)
            throws CertificateEncodingException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException, OperatorCreationException, IllegalNameException,
            AuthorizationDeniedException, CertificateExtensionException, KeyArchivalException {

        Certificate kec = currentKecCache.get(cAId);

        log.error("KEC CACHE size is " + currentKecCache.size());

        log.error("KEC CACHE is empty " + currentKecCache.isEmpty());

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

    public void flushKecCache() {
        currentKecCache = new ConcurrentHashMap<>();
        log.info("KEC cache cleared.");
        log.error(" The cache is now empty : " + currentKecCache.isEmpty());
        log.error(" The size of cache is now : " + currentKecCache.size());
    }

    private Certificate generateKecOnCaSideAndCache(final AuthenticationToken admin, final int cAId, final int cPId)
            throws AuthorizationDeniedException, InvalidAlgorithmException, CryptoTokenOfflineException, CertificateCreateException,
            CertificateExtensionException, CAOfflineException, IllegalValidityException, SignatureException, IllegalKeyException,
            OperatorCreationException, IllegalNameException, CertificateEncodingException, KeyArchivalException {
        Certificate kec;
        kec = raMasterApiProxyBean.getKeyExchangeCertificate(admin, cAId, cPId);
        if (Objects.isNull(kec)) {
            log.debug("RaMasterApi returns null instead of key exchange certificate.");
            throw new KeyArchivalException("Null key exchange certificate returned by the CA!");
        } else {
            currentKecCache.put(cAId, kec);
        }
        return kec;
    }

}
