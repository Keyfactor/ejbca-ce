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

package org.ejbca.core.ejb.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.CertTools;

/**
 * Some test methods that are used from system tests
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CAAdminTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CAAdminTestSessionBean implements CAAdminTestSessionRemote {

    private static final Logger log = Logger.getLogger(CAAdminTestSessionBean.class);
    
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public String getKeyFingerPrint(String caname) throws CADoesntExistsException, UnsupportedEncodingException, IllegalCryptoTokenException, CryptoTokenOfflineException, NoSuchAlgorithmException {
    	CAData cadata = caSession.findByNameOrThrow(caname);
    	CA thisCa = cadata.getCA();//getCAFromDatabase(cadata.getCaId());
    	// Fetch keys
    	CAToken thisCAToken = thisCa.getCAToken();
    	final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(thisCAToken.getCryptoTokenId());
    	// Make sure we are not trying to export a hard or invalid token
    	if (!(cryptoToken instanceof SoftCryptoToken)) {
    		throw new IllegalCryptoTokenException("Cannot extract fingerprint from a non-soft token (" + thisCa.getCAType() + ").");
    	}
    	PrivateKey p12PrivateEncryptionKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
    	PrivateKey p12PrivateCertSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
    	PrivateKey p12PrivateCRLSignKey = cryptoToken.getPrivateKey(thisCAToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CRLSIGN));
    	MessageDigest md = MessageDigest.getInstance("SHA1");
    	md.update(p12PrivateEncryptionKey.getEncoded());
    	md.update(p12PrivateCertSignKey.getEncoded());
    	md.update(p12PrivateCRLSignKey.getEncoded());
    	return new String(Hex.encode(md.digest()));
    }
    
    @Override
    public void clearCertData(Certificate cert) {
        final String fingerprint = CertTools.getFingerprintAsString(cert);
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (cdw.getBase64CertData()!=null) {
            log.info("Resetting base64 data of certificate with fingerprint '" + fingerprint + "' by removing Base64CertData entity.");
            final Query deleteQuery = entityManager.createQuery("DELETE FROM Base64CertData a WHERE a.fingerprint=:fingerprint");
            deleteQuery.setParameter("fingerprint", fingerprint);
            final int updatedRows = deleteQuery.executeUpdate();
            if (updatedRows!=1) {
                log.warn("Failed to reset base64 data of certificate with fingerprint '\" + fingerprint + \"'.");
            }
        } else {
            log.info("Resetting base64 data of certificate with fingerprint '" + fingerprint + "' by setting CertificateData.base64Cert to ''.");
            cdw.getCertificateData().setBase64Cert("");
            entityManager.merge(cdw.getCertificateData());
        }
    }
}
