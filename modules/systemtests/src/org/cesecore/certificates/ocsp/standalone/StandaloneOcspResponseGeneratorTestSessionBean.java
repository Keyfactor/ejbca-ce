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
package org.cesecore.certificates.ocsp.standalone;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.cache.TokenAndChainCache;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.jndi.JndiConstants;

/**
 * Test session bean used to do some nasty manipulation on StandaloneOcspResponseGeneratorSessionBean
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "StandaloneOcspResponseGeneratorTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class StandaloneOcspResponseGeneratorTestSessionBean extends StandaloneOcspResponseGeneratorSessionBean implements
        StandaloneOcspResponseGeneratorTestSessionRemote, StandaloneOcspResponseGeneratorTestSessionLocal {

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    
    @Override
    public void replaceTokenAndChainCache(Map<Integer, CryptoTokenAndChain> newCache) throws CertificateEncodingException, OCSPException {
        TokenAndChainCache cache = getTokenAndChainCache();
        X509Certificate latestCertificate = certificateStoreSession.findLatestX509CertificateBySubject(OcspConfiguration.getDefaultResponderId());
        cache.updateCache(newCache, new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), latestCertificate, new BigInteger("1")));
    }
    
    @Override
    public Collection<CryptoTokenAndChain> getCacheValues() {
        return super.getCacheValues();
    }
}

