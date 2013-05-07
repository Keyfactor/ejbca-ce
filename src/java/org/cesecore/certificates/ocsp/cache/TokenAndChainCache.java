/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp.cache;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.CacheNotInitializedException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

/**
 * This class represents a cache for CryptoTokenAndChain objects (the key used to access them can be produced locally in this class), as well as the
 * latest default responder certificate. The reason that this class isn't singleton implemented is that different implementations of the OCSP
 * responder may be in use at the same time.  
 * 
 * @version $Id$
 * 
 */
@Deprecated // TODO: Remove
public final class TokenAndChainCache {

    private Map<Integer, CryptoTokenAndChain> cache;

    private CertificateID latestDefaultResponderCertificateID;

    public TokenAndChainCache() {

    }

    public boolean containsKey(CertificateID certificateID) {
        if (cache == null) {
            throw new CacheNotInitializedException("Token and chain cache has not been initialized, this is an implementation error.");
        } 
        return cache.containsKey(keyFromCertificateID(certificateID));
    }
    
    public boolean containsKey(Integer key) {
        if (cache == null) {
            throw new CacheNotInitializedException("Token and chain cache has not been initialized, this is an implementation error.");
        } 
        
        return cache.containsKey(key);
    }
    
    /**
     * This getter calculates the key from the given certificate and returns the matching CryptoTokenAndChain, if any.
     * 
     * @param certificate a CA certificate
     * @return the sought CryptoTokenAndChain, null if not found.
     */
    public CryptoTokenAndChain get(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        } else {
            CertificateID certId = null;
            try {
                certId = new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(),  certificate, certificate.getSerialNumber());
            } catch (OCSPException e) {
                throw new OcspFailureException(e);
            } catch (CertificateEncodingException e) {
                throw new OcspFailureException(e);
            } 
            return get(keyFromCertificateID(certId));
        }
    }

    public CryptoTokenAndChain get(CertificateID key) {
        return get(keyFromCertificateID(key));
    }

    public CryptoTokenAndChain get(Integer key) {
        if (cache == null) {
            throw new CacheNotInitializedException("Token and chain cache has not been initialized, this is an implementation error.");
        } else if(key == null) {
            return null;
        } else {
            return cache.get(key);
        }
    }
    
    public Collection<CryptoTokenAndChain> values() {
        if (cache == null) {
            throw new CacheNotInitializedException("Token and chain cache has not been initialized, this is an implementation error.");
        } else {
            return cache.values();
        }
    }

    /**
     * This method replaces the existing cache with the one in the argument.
     * 
     * @param newCache the new cache.
     */
    public void updateCache(Map<Integer, CryptoTokenAndChain> newCache, CertificateID latestDefaultResponderCertificateID) {
        this.cache = newCache;
        this.latestDefaultResponderCertificateID = latestDefaultResponderCertificateID;
    }

    public CryptoTokenAndChain getForDefaultResponder() {
        return get(latestDefaultResponderCertificateID);
    }

    /**
     * This method converts a certID into an integer identifier, based on a bitwise addition of the respective hashcodes of the IssuerNameHash and
     * IssuerKeyHash.
     * 
     * @param certID
     * @return
     */
    public static Integer keyFromCertificateID(CertificateID certID) {
        if (certID == null) {
            return null;
        } else {
            Integer result =  Integer.valueOf(new BigInteger(certID.getIssuerNameHash()).hashCode() ^ new BigInteger(certID.getIssuerKeyHash()).hashCode());
            System.err.println(certID.hashCode() + ", " + result);
            return result;
        }
    }

    /**
     * 
     * @return whether or not this singleton is ready to run, or needs to be updated first.
     */
    public boolean isInitiated() {
        return cache != null;
    }

}
