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

import javax.ejb.Remote;

/**
 * Remote interface for CertificateStoreOnlyDataSession.
 */
@Remote
public interface CertificateStoreOnlyDataSessionRemote {
    /**
     * Get status fast
     * 
     * @param issuerDN
     * @param serno
     * @return the status of the certificate
     */
    public org.ejbca.core.ejb.ca.store.CertificateStatus getStatus(java.lang.String issuerDN, java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Finds a certificate specified by issuer DN and serial number.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param issuerDN
     *            issuer DN of the desired certificate.
     * @param serno
     *            serial number of the desired certificate!
     * @return Certificate if found or null
     */
    public java.security.cert.Certificate findCertificateByIssuerAndSerno(org.ejbca.core.model.log.Admin admin, java.lang.String issuerDN,
            java.math.BigInteger serno) throws java.rmi.RemoteException;

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     * <p/>
     * The type is the bitwise OR value of the types listed int
     * {@link org.ejbca.core.ejb.ca.store.CertificateDataBean}:<br>
     * <ul>
     * <li><tt>CERTTYPE_ENDENTITY</tt><br>
     * An user or machine certificate, which identifies a subject.</li>
     * <li><tt>CERTTYPE_CA</tt><br>
     * A CA certificate which is <b>not</b> a root CA.</li>
     * <li><tt>CERTTYPE_ROOTCA</tt><br>
     * A Root CA certificate.</li>
     * </ul>
     * <p/>
     * Usage examples:<br>
     * <ol>
     * <li>Get all root CA certificates
     * <p/>
     * <code> ... ICertificateStoreOnlyDataSessionRemote itf = ... Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_ROOTCA, null); ... </code>
     * </li>
     * <li>Get all subordinate CA certificates for a specific Root CA. It is
     * assumed that the <tt>subjectDN</tt> of the Root CA certificate is located
     * in the variable <tt>issuer</tt>.
     * <p/>
     * <code> ... ICertificateStoreOnlyDataSessionRemote itf = ... Certficate rootCA = ... String issuer = rootCA.getSubjectDN(); Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_SUBCA, issuer); ... </code>
     * </li>
     * <li>Get <b>all</b> CA certificates.
     * <p/>
     * <code> ... ICertificateStoreOnlyDataSessionRemote itf = ... Collection certs = itf.findCertificatesByType(adm, CertificateDataBean.CERTTYPE_SUBCA + CERTTYPE_ROOTCA, null); ... </code>
     * </li>
     * </ol>
     * 
     * @param admin
     * @param issuerDN
     *            get all certificates issued by a specific issuer. If
     *            <tt>null</tt> or empty return certificates regardless of the
     *            issuer.
     * @param type
     *            CERTTYPE_* types from CertificateDataBean
     * @return Collection Collection of X509Certificate, never <tt>null</tt>
     */
    public java.util.Collection findCertificatesByType(org.ejbca.core.model.log.Admin admin, int type, java.lang.String issuerDN)
            throws java.rmi.RemoteException;

    /**
     * Finds certificate(s) for a given username.
     * 
     * @param admin
     *            Administrator performing the operation
     * @param username
     *            the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or null if none found.
     */
    public java.util.Collection findCertificatesByUsername(org.ejbca.core.model.log.Admin admin, java.lang.String username) throws java.rmi.RemoteException;
}
