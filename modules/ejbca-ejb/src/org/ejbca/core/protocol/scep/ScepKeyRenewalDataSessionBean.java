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

package org.ejbca.core.protocol.scep;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import com.keyfactor.util.CertTools;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ScepKeyRenewalDataSessionBean implements ScepKeyRenewalDataSessionLocal, ScepKeyRenewalDataSessionRemote {

	private static final Logger log = Logger.getLogger(ScepKeyRenewalDataSessionBean.class);

	@PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
	private EntityManager entityManager;

	@EJB
	private GlobalConfigurationSessionLocal globalConfigSession;
	@EJB
	private EndEntityManagementSessionLocal endEntityManagementSession;
	@EJB
	private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
	@EJB
	private CertificateCreateSessionLocal certificateCreateSession;
	@EJB
	private CaSessionLocal caSession;

	private ScepRaCertificateIssuer scepRaCertificateIssuer;

	private final AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken(
			new UsernamePrincipal(ScepKeyRenewalSessionBean.class.getSimpleName()));

	@Override
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void renewScepKeys() {
		var scepConfiguration = (ScepConfiguration) globalConfigSession.getCachedConfigurationAndLockWrites(
				ScepConfiguration.SCEP_CONFIGURATION_ID);
		boolean updatedKeys = false;
		for (var alias : scepConfiguration.getAliasList()) {
		    
            if (scepConfiguration.getRAMode(alias)) {
                var encryptionKey = scepConfiguration.getEncryptionCertificateForCa(alias, null);
                var signKey = scepConfiguration.getSigningCertificateForCa(alias, null);
                try {
                    if (encryptionKey != null && shouldRenew(encryptionKey)) {
                        var caName = scepConfiguration.getRADefaultCA(alias);
                        var cryptoTokenId = scepConfiguration.getEncryptionCryptoTokenId(alias);
                        var encryptionKeyAlias = scepConfiguration.getEncryptionKeyAlias(alias);
                        var encryptionCertificate = getScepRaCertificateIssuer().issueEncryptionCertificate(authenticationToken, caName,
                                cryptoTokenId, encryptionKeyAlias);
                        var pemEncryptionCertificate = CertTools.getPemFromCertificate(encryptionCertificate);
                        log.info(String.format("Renewed SCEP certificate %s %s %s", encryptionCertificate.getSubjectDN(),
                                encryptionCertificate.getNotAfter(), encryptionCertificate.getSerialNumber()));
                        scepConfiguration.setEncryptionCertificate(alias, pemEncryptionCertificate);
                        updatedKeys = true;
                    }
                    if (signKey != null && shouldRenew(signKey)) {
                        var caName = scepConfiguration.getRADefaultCA(alias);
                        var cryptoTokenId = scepConfiguration.getSigningCryptoTokenId(alias);
                        var signingKeyAlias = scepConfiguration.getSigningKeyAlias(alias);
                        var signingCertificate = getScepRaCertificateIssuer().issueSigningCertificate(authenticationToken, caName, cryptoTokenId,
                                signingKeyAlias);
                        var pemSigningCertificate = CertTools.getPemFromCertificate(signingCertificate);
                        log.info(String.format("Renewed SCEP certificate %s %s %s", signingCertificate.getSubjectDN(),
                                signingCertificate.getNotAfter(), signingCertificate.getSerialNumber()));
                        scepConfiguration.setSigningCertificate(alias, pemSigningCertificate);
                        updatedKeys = true;
                    }
                } catch (ScepEncryptionCertificateIssuanceException e) {
                    log.error(String.format("Unable to renew SCEP keys for %s", alias), e);
                } catch (CertificateEncodingException e) {
                    //Shouldn't happen
                    log.error(String.format("Unable to get PEM from certificate %s", alias), e);
                }
            } else {
                var encryptionCertificates = scepConfiguration.getEncryptionCertificates(alias);
                var signingCertificates = scepConfiguration.getSigningCertificates(alias);
                
                // are we in CA mode with separate encryption/signing keys?
                if (encryptionCertificates != null && signingCertificates != null) {
                    var encryptionCryptoTokenId = scepConfiguration.getEncryptionCryptoTokenId(alias);
                    var encryptionKeyAlias = scepConfiguration.getEncryptionKeyAlias(alias);
                    var signingCryptoTokenId = scepConfiguration.getSigningCryptoTokenId(alias);
                    var signingKeyAlias = scepConfiguration.getSigningKeyAlias(alias);
                    
                    var casWithCertificates = encryptionCertificates.keySet();
                    for (String ca : casWithCertificates) {
                        // renew the encryption certificate
                        try {
                            X509Certificate encryptionCertificate = scepConfiguration.getEncryptionCertificateForCa(alias, ca);
                            if (shouldRenew(encryptionCertificate)) {
                                var newEncryptionCertificate = getScepRaCertificateIssuer().issueEncryptionCertificate(authenticationToken, ca,
                                        encryptionCryptoTokenId, encryptionKeyAlias);
                                var pemCertificate = CertTools.getPemFromCertificate(newEncryptionCertificate);
                                log.info(String.format("Renewed SCEP encryption certificate %s %s %s",
                                        newEncryptionCertificate.getSubjectX500Principal().toString(), newEncryptionCertificate.getNotAfter(),
                                        newEncryptionCertificate.getSerialNumber()));
                                encryptionCertificates.put(ca, pemCertificate);
                                updatedKeys = true;
                            }
                        } catch (ScepEncryptionCertificateIssuanceException e) {
                            log.error(String.format("Unable to renew SCEP keys for %s", alias), e);
                        } catch (CertificateEncodingException e) {
                            //Shouldn't happen
                            log.error(String.format("Unable to get PEM from certificate %s", alias), e);
                        }

                        // renew the signing certificate
                        try {
                            X509Certificate SigningCertificate = scepConfiguration.getSigningCertificateForCa(alias, ca);
                            if (shouldRenew(SigningCertificate)) {
                                var newSigningCertificate = getScepRaCertificateIssuer().issueSigningCertificate(authenticationToken, ca,
                                        signingCryptoTokenId, signingKeyAlias);
                                var pemCertificate = CertTools.getPemFromCertificate(newSigningCertificate);
                                log.info(String.format("Renewed SCEP signing certificate %s %s %s",
                                        newSigningCertificate.getSubjectX500Principal().toString(), newSigningCertificate.getNotAfter(),
                                        newSigningCertificate.getSerialNumber()));
                                signingCertificates.put(ca, pemCertificate);
                                updatedKeys = true;
                            }
                        } catch (ScepEncryptionCertificateIssuanceException e) {
                            log.error(String.format("Unable to renew SCEP keys for %s", alias), e);
                        } catch (CertificateEncodingException e) {
                            //Shouldn't happen
                            log.error(String.format("Unable to get PEM from certificate %s", alias), e);
                        }
                    }
                }
                
                scepConfiguration.setEncryptionCertificates(alias, encryptionCertificates);
                scepConfiguration.setSigningCertificates(alias, signingCertificates);
            }
		}

		if (updatedKeys) {
			try {
				globalConfigSession.saveConfiguration(authenticationToken, scepConfiguration);
			} catch (AuthorizationDeniedException e) {
				//Shouldn't happen
				throw new RuntimeException(e);
			}
		}
	}

	private boolean shouldRenew(X509Certificate keyCertificate) {
		var now = new Date();
		var millisThreshold = TimeUnit.DAYS.toMillis(5);
		var thresholdDate = new Date(now.getTime() + millisThreshold);

		if (keyCertificate.getNotAfter().before(thresholdDate)) {
			log.info(String.format("SCEP certificate %s %s %s will be renewed", keyCertificate.getSubjectDN(),
					keyCertificate.getNotAfter(), keyCertificate.getSerialNumber()));
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Creates or get the Scep Cerificate Issuer
	 */
	public ScepRaCertificateIssuer getScepRaCertificateIssuer() {
		if (scepRaCertificateIssuer == null) {
			scepRaCertificateIssuer = new ScepRaCertificateIssuer(cryptoTokenManagementSession, caSession,
					endEntityManagementSession, certificateCreateSession);
		}
		return scepRaCertificateIssuer;
	}

}
