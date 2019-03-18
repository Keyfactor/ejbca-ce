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
package org.cesecore.certificates.ca;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.internal.IUpgradeableData;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * Interface containing common methods for all CA implementaations
 * @version $Id$
 *
 */
public interface CACommon extends IUpgradeableData {

    String getCaImplType();
    
    void init(CAInfo cainfo);

    /** Constructor used when retrieving existing CA from database. */
    void init(HashMap<Object, Object> data);

    void setCAInfo(CAInfo cainfo);

    CAInfo getCAInfo();

    String getSubjectDN();

    void setSubjectDN(String subjectDn);
    
    String getSubjectAltName();
    
    void setSubjectAltName(final String altName);

    int getCAId();

    void setCAId(int caid);

    String getName();

    void setName(String caname);

    int getStatus();

    void setStatus(int status);

    int getCertificateProfileId();
    
    Collection<Integer> getValidators();

    void setValidators(Collection<Integer> validators);
    
    long getValidity();

    /**
     * Gets the validity.
     * @return the validity as ISO8601 date or relative time.
     * @See {@link org.cesecore.util.ValidityDate ValidityDate}
     */
    String getEncodedValidity();
    
    /**
     * Sets the validity as relative time (format '*y *mo *d *h *m *s', i.e. '1y +2mo -3d 4h 5m 6s') or as fixed end date
     * (ISO8601 format, i.e. 'yyyy-MM-dd HH:mm:ssZZ', 'yyyy-MM-dd HH:mmZZ' or 'yyyy-MM-ddZZ' with optional '+00:00' appended).
     *
     * @param encodedValidity
     */
    void setEncodedValidity(String encodedValidity);
    
    /**
     * @return one of CAInfo.CATYPE_CVC or CATYPE_X509
     */
    int getCAType();

    Date getExpireTime();

    void setExpireTime(Date expiretime);

    int getSignedBy();

    void setSignedBy(int signedby);

    String getDescription();

    void setDescription(String description);

    int getRevocationReason();

    void setRevocationReason(int reason);

    Date getRevocationDate();

    void setRevocationDate(Date date);

    /** @return the CAs token reference. */
    CAToken getCAToken();

    /** Sets the CA token. */
    void setCAToken(CAToken catoken) throws InvalidAlgorithmException;

    /** Returns a collection of CA certificates, or null if no request certificate chain exists */
    Collection<Certificate> getRequestCertificateChain();

    void setRequestCertificateChain(Collection<Certificate> requestcertificatechain);

    /**
     * Returns a collection of CA-certificates, with this CAs cert i position 0, or null if no CA-certificates exist. The root CA certificate will
     * thus be in the last position.
     *
     * @return Collection of Certificate
     */
    List<Certificate> getCertificateChain();

    void setCertificateChain(List<Certificate> certificatechain);

    /**
     * @return the list of renewed CA certificates in order from the oldest as first to the newest as the last one
     */
    List<Certificate> getRenewedCertificateChain();

    /**
     * Make sure to respect the order of renewed CA certificates in the collection: from the oldest as first to the newest as the last one
     * @param certificatechain collection of the renewed CA certificates to be stored
     */
    void setRenewedCertificateChain(List<Certificate> certificatechain);

    void setRolloverCertificateChain(Collection<Certificate> certificatechain);

    List<Certificate> getRolloverCertificateChain();

    void clearRolloverCertificateChain();
    
    /** Create a certificate with all the current CA certificate info, but signed by the old issuer */
    void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException;
    
    /** @return the CA latest link certificate or null */
    byte[] getLatestLinkCertificate();

    /** Returns the CAs certificate, or null if no CA-certificates exist. */
    Certificate getCACertificate();

    /** Returns true if we should use the next CA certificate for rollover, instead of the current CA certificate. */
    boolean getUseNextCACert(RequestMessage request);

    void updateCA(CryptoToken cryptoToken, CAInfo cainfo, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws InvalidAlgorithmException;

    /**
     * Called when an uninitialized CA is updated, either from updateCA
     * or from other places in the code.
     *
     * A few more values are also set in the overridden method in X509CA.
     */
    void updateUninitializedCA(CAInfo cainfo);
    
    
    Collection<Integer> getCRLPublishers();
    
    void setCRLPublishers(Collection<Integer> crlpublishers);
    
    /**
     * @return A 1:1 mapping between Approval Action:Approval Profile ID
     */
    Map<ApprovalRequestType, Integer> getApprovals();

    void setApprovals(Map<ApprovalRequestType, Integer> approvals);

    /**
     * @return a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals,
     * default none and never null.
     *
     * @deprecated since 6.8.0, see getApprovals()
     */
    Collection<Integer> getApprovalSettings();

    /**
     * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals
     *
     * @deprecated since 6.8.0, see setApprovals()
     */
    void setApprovalSettings(Collection<Integer> approvalSettings);

    /**
     * @return the number of different administrators that needs to approve an action, default 1.
     * @deprecated since 6.6.0, use the appropriate approval profile instead.
     * Needed in order to be able to upgrade from 6.5 and earlier
     */
    int getNumOfRequiredApprovals();

    /**
     * The number of different administrators that needs to approve
     * @deprecated since 6.6.0, use the appropriate approval profile instead.
     * Needed in order to be able to upgrade from 6.5 and earlier
     */
    void setNumOfRequiredApprovals(int numOfReqApprovals);

    /**
     * @return the id of the approval profile. Defult -1 (= none)
     *
     * @deprecated since 6.8.0, see getApprovals()
     */
    int getApprovalProfile();

    /**
     * The id of the approval profile.
     *
     * @deprecated since 6.8.0, see setApprovals()
     */
    void setApprovalProfile(int approvalProfileID);
    
    /**
     * Method to upgrade new (or existing externacaservices) This method needs to be called outside the regular upgrade since the CA isn't
     * instantiated in the regular upgrade.
     */
    boolean upgradeExtendedCAServices();
    
    /**
     * Implementation of UpgradableDataHashMap function upgrade.
     */
    void upgrade();
}
