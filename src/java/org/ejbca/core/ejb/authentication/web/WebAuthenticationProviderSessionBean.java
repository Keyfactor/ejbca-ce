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
package org.ejbca.core.ejb.authentication.web;

import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.log.LogConstants;

/**
 *
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "WebAuthenticationProviderSessionLocal")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class WebAuthenticationProviderSessionBean implements WebAuthenticationProviderSessionLocal {

    private static final long serialVersionUID = 1524951666783567785L;

    private final static Logger LOG = Logger.getLogger(WebAuthenticationProviderSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;

    /**
     * Performs client certificate authentication for a subject. This requires:
     * - An AuthenticationSubject containing a Set<X509Certificate>, where there should be only one certificate 
     *   being the administrators client certificate.
     * If the admin certificate is required to be in the database (properties configuration option) it is
     * verified that the certificate is present in the database and that it is not revoked.
     * 
     * @param subject an AuthenticationSubject containing a Set<X509Certificate> of credentials, the set must contain one certificate which is the admin client certificate.
     * @return an AuthenticationToken if the subject was authenticated, null otherwise.
     */
    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {
        @SuppressWarnings("unchecked")
        final Set<X509Certificate> certs = (Set<X509Certificate>) subject.getCredentials();
        if (certs.size() != 1) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("certificateArray contains "+certs.size()+" certificates, instead of 1 that is required.");
            }
            return null;
        } else {
            final X509Certificate certificate = certs.iterator().next();
            // Check Validity
            try {
                certificate.checkValidity();
            } catch (Exception e) {
                final String msg = intres.getLocalizedMessage("authentication.certexpired", CertTools.getSubjectDN(certificate), CertTools.getNotAfter(certificate).toString());
            	LOG.info(msg);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                securityEventsLoggerSession.log(EventTypes.AUTHENTICATION, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA, LogConstants.NO_AUTHENTICATION_TOKEN, null, null, null, details);
            	return null;
            }
            // Find out if this is a certificate present in the local database (even if we don't require a cert to be present there we still want to allow a mix)
            final CertificateInfo certificateInfo = certificateStoreSession.findFirstCertificateInfo(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate));
            if (certificateInfo != null) {
                // The certificate is present in the database.
                if (!(certificateInfo.getStatus() == CertificateConstants.CERT_ACTIVE || certificateInfo.getStatus() == CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION)) {
                    // The certificate is neither active, nor active (but user is notified of coming revocation)
                    final String msg = intres.getLocalizedMessage("authentication.revokedormissing", CertTools.getSubjectDN(certificate));
                    LOG.info(msg);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    securityEventsLoggerSession.log(EventTypes.AUTHENTICATION, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA, LogConstants.NO_AUTHENTICATION_TOKEN, null, null, null, details);
                    return null;
                }
            } else {
                // The certificate is not present in the database.
                if (WebConfiguration.getRequireAdminCertificateInDatabase()) {
                    final String msg =  intres.getLocalizedMessage("authentication.revokedormissing", CertTools.getSubjectDN(certificate));
                    LOG.info(msg);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    securityEventsLoggerSession.log(EventTypes.AUTHENTICATION, EventStatus.FAILURE, EjbcaModuleTypes.ADMINWEB, EjbcaServiceTypes.EJBCA, LogConstants.NO_AUTHENTICATION_TOKEN, null, null, null, details);
                    return null;
                }
                // TODO: We should check the certificate for CRL or OCSP tags and verify the certificate status
            }
            final Set<X500Principal> principals = new HashSet<X500Principal>();
            principals.add(certificate.getSubjectX500Principal());
            final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(certificate);
            return new X509CertificateAuthenticationToken(principals, credentials);
        }

    }

}
