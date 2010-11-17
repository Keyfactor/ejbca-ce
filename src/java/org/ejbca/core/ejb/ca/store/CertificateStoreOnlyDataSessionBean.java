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

package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CryptoProviderTools;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateStoreOnlyDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreOnlyDataSessionBean extends CertificateDataUtil implements CertificateStoreOnlyDataSessionLocal, CertificateStoreOnlyDataSessionRemote {
    
    private static final Logger log = Logger.getLogger(CertificateStoreOnlyDataSessionBean.class);
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    public CertificateStoreOnlyDataSessionBean() {
        super();
        CryptoProviderTools.installBCProvider();
    }

    /**
     * Used by healthcheck. Validate database connection.
     * @return an error message or an empty String if all are ok.
     * 
     */
    public String getDatabaseStatus() {
		String returnval = "";
		try {
			entityManager.createNativeQuery(EjbcaConfiguration.getHealthCheckDbQuery()).getResultList();
			// TODO: Do we need to flush() the connection to avoid that this is executed in a batch after the method returns?
		} catch (Exception e) {
			returnval = "\nDB: Error creating connection to database: " + e.getMessage();
			log.error("Error creating connection to database.",e);
		}
		return returnval;
    }

    /**
     * Get status fast
     * 
     * @param issuerDN
     * @param serno
     * @return the status of the certificate
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return getStatus(issuerDN, serno, entityManager);
    }

    /**
     * Finds a certificate specified by issuer DN and serial number.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno    serial number of the desired certificate!
     * @return Certificate if found or null
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
    	return findCertificateByIssuerAndSerno(admin, issuerDN, serno, entityManager);
    }

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     * <p/>
     * The type is the bitwise OR value of the types listed
     * int {@link org.ejbca.core.ejb.ca.store.CertificateDataBean}:<br>
     * <ul>
     * <li><tt>CERTTYPE_ENDENTITY</tt><br>
     * An user or machine certificate, which identifies a subject.
     * </li>
     * <li><tt>CERTTYPE_CA</tt><br>
     * A CA certificate which is <b>not</b> a root CA.
     * </li>
     * <li><tt>CERTTYPE_ROOTCA</tt><br>
     * A Root CA certificate.
     * </li>
     * </ul>
     * <p/>
     * Usage examples:<br>
     * <ol>
     * <li>Get all root CA certificates
     * <p/>
     * <code>
     * ...
     * ICertificateStoreOnlyDataSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * <li>Get all subordinate CA certificates for a specific
     * Root CA. It is assumed that the <tt>subjectDN</tt> of the
     * Root CA certificate is located in the variable <tt>issuer</tt>.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreOnlyDataSessionRemote itf = ...
     * Certficate rootCA = ...
     * String issuer = rootCA.getSubjectDN();
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA,
     * issuer);
     * ...
     * </code>
     * </li>
     * <li>Get <b>all</b> CA certificates.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreOnlyDataSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA
     * + CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * </ol>
     *
     * @param admin
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from CertificateDataBean
     * @return Collection Collection of X509Certificate, never <tt>null</tt>
     */
    public Collection<Certificate> findCertificatesByType(Admin admin, int type, String issuerDN) {
        return findCertificatesByType(admin, type, issuerDN, entityManager);
    }

    /**
     * Finds certificate(s) for a given username.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last expire date first, or null if none found.
     */
    public Collection<Certificate> findCertificatesByUsername(Admin admin, String username) {
    	return findCertificatesByUsername(admin, username, entityManager);
    }
}
