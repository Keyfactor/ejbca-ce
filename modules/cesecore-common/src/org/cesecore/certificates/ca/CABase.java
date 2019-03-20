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

import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;

/**
 * CA is a base class that should be inherited by all CA types
 *
 * @version $Id$
 */
public abstract class CABase extends CABaseCommon implements Serializable, CA {

    private static final long serialVersionUID = -8755429830955594642L;

    /** Log4j instance */
    private static Logger log = Logger.getLogger(CABase.class);
    /** Internal localization of logs and errors */

    // protected fields.
    protected static final String SUBJECTDN = "subjectdn";
    protected static final String CAID = "caid";
    public static final String NAME = "name";
    protected static final String CERTIFICATECHAIN = "certificatechain";
    protected static final String RENEWEDCERTIFICATECHAIN = "renewedcertificatechain";
    protected static final String ROLLOVERCERTIFICATECHAIN = "rollovercertificatechain";
    public static final String CATOKENDATA = "catoken";

    protected static final String CERTIFICATEPROFILEID = "certificateprofileid";
    protected static final String DEFAULTCERTIFICATEPROFILEID = "defaultcertificateprofileid";

    protected static final String CRLISSUEINTERVAL = "crlIssueInterval";
    protected static final String CRLOVERLAPTIME = "crlOverlapTime";
    protected static final String CRLPUBLISHERS = "crlpublishers";
    protected static final String VALIDATORS = "keyvalidators";
    private static final String FINISHUSER = "finishuser";
    protected static final String REQUESTCERTCHAIN = "requestcertchain";
    protected static final String EXTENDEDCASERVICES = "extendedcaservices";
    protected static final String EXTENDEDCASERVICE = "extendedcaservice";
    protected static final String USENOCONFLICTCERTIFICATEDATA = "usenoconflictcertificatedata";
    protected static final String SERIALNUMBEROCTETSIZE = "serialnumberoctetsize";

    /**
     * @deprecated since 6.8.0, replaced by the approvals Action:ApprovalProfile mapping
     */
    @Deprecated
    private static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = "doEnforceUniquePublicKeys";
    private static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = "doEnforceUniqueDistinguishedName";
    private static final String DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER = "doEnforceUniqueSubjectDNSerialnumber";
    private static final String USE_CERTREQ_HISTORY = "useCertreqHistory";
    private static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";
    private static final String ACCEPT_REVOCATION_NONEXISTING_ENTRY = "acceptRevocationNonExistingEntry";
    private static final String KEEPEXPIREDCERTSONCRL = "keepExpiredCertsOnCRL";
    
    /**
     * @deprecated since 6.8.0, replaced by the approvals Action:ApprovalProfile mapping
     */
    @Deprecated
    protected static final String APPROVALSETTINGS = "approvalsettings";
    /**
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed in order to be able to upgrade from 6.5 and earlier
     */
    @Deprecated
    protected static final String NUMBEROFREQAPPROVALS = "numberofreqapprovals";

    protected static final String INCLUDEINHEALTHCHECK = "includeinhealthcheck";
    private static final String USE_USER_STORAGE = "useUserStorage";

    /** No args constructor required for ServiceLocator */
    protected CABase() {
    }

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public CABase(CAInfo cainfo) {
        init(cainfo);
    }

    public void init(CAInfo cainfo) {
        data = new LinkedHashMap<>();
        super.init(cainfo);
        data.put(USENOCONFLICTCERTIFICATEDATA, cainfo.isUseNoConflictCertificateData());
        if (!cainfo.isUseCertificateStorage()) {
            data.put(DEFAULTCERTIFICATEPROFILEID, Integer.valueOf(cainfo.getDefaultCertificateProfileId()));
        }
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName());
        setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        setUseCertReqHistory(cainfo.isUseCertReqHistory());
        setUseUserStorage(cainfo.isUseUserStorage());
        setUseCertificateStorage(cainfo.isUseCertificateStorage());
        setAcceptRevocationNonExistingEntry(cainfo.isAcceptRevocationNonExistingEntry());
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL());
        setCRLPeriod(cainfo.getCRLPeriod());
        setCRLIssueInterval(cainfo.getCRLIssueInterval());
        setCRLOverlapTime(cainfo.getCRLOverlapTime());
        setDeltaCRLPeriod(cainfo.getDeltaCRLPeriod());
        
        ArrayList<Integer> extendedservicetypes = new ArrayList<>();
        for(ExtendedCAServiceInfo next : cainfo.getExtendedCAServiceInfos()) {
            createExtendedCAService(next);
            if (log.isDebugEnabled()) {
                log.debug("Adding extended service to CA '"+cainfo.getName()+"': "+next.getType()+", "+next.getImplClass());
            }
            extendedservicetypes.add(next.getType());
        }
        data.put(EXTENDEDCASERVICES, extendedservicetypes);
        setApprovals(cainfo.getApprovals());
    }

    /** Constructor used when retrieving existing CA from database. */
    public void init(HashMap<Object, Object> data) {
        super.init(data);
    }
    
    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        super.updateCA(cryptoToken, cainfo, cceConfig);
        data.put(CRLPERIOD, Long.valueOf(cainfo.getCRLPeriod()));
        data.put(DELTACRLPERIOD, Long.valueOf(cainfo.getDeltaCRLPeriod()));
        data.put(CRLISSUEINTERVAL, Long.valueOf(cainfo.getCRLIssueInterval()));
        data.put(CRLOVERLAPTIME, Long.valueOf(cainfo.getCRLOverlapTime()));
        data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
        data.put(VALIDATORS, cainfo.getValidators());
        data.put(USENOCONFLICTCERTIFICATEDATA, cainfo.isUseNoConflictCertificateData());
        if (cainfo.getDefaultCertificateProfileId() > 0 && !cainfo.isUseCertificateStorage()) {
            data.put(DEFAULTCERTIFICATEPROFILEID, Integer.valueOf(cainfo.getDefaultCertificateProfileId()));
        }
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL());
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName());
        setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        setUseCertReqHistory(cainfo.isUseCertReqHistory());
        setUseUserStorage(cainfo.isUseUserStorage());
        setUseCertificateStorage(cainfo.isUseCertificateStorage());
        setAcceptRevocationNonExistingEntry(cainfo.isAcceptRevocationNonExistingEntry());
        // Update or create extended CA services
        final Collection<ExtendedCAServiceInfo> infos = cainfo.getExtendedCAServiceInfos();
        if (infos != null) {
            final Collection<ExtendedCAServiceInfo> newInfos = new ArrayList<>();
            Collection<Integer> extendedservicetypes = getExternalCAServiceTypes(); // Se we can add things to this
            for (ExtendedCAServiceInfo info : infos) {
                ExtendedCAService service = this.getExtendedCAService(info.getType());
                if (service == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Creating new extended CA service of type: "+info.getType());
                    }
                    createExtendedCAService(info);
                    extendedservicetypes.add(info.getType());
                    newInfos.add(info);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Updating extended CA service of type: "+info.getType());
                    }
                    service.update(cryptoToken, info, (CABase)this, cceConfig); // the service's signing certificate might get created at this point!
                    setExtendedCAService(service);

                    // Now read back the info object from the service.
                    // This is necessary because the service's signing certificate is "lazy-created",
                    // i.e. created when the service becomes active the first time.
                    final ExtendedCAServiceInfo newInfo = service.getExtendedCAServiceInfo();
                    newInfos.add(newInfo);
                }
            }
            cainfo.setExtendedCAServiceInfos(newInfos);
            data.put(EXTENDEDCASERVICES, extendedservicetypes);
        }
    }
    
    public long getCRLPeriod() {
        return ((Long) data.get(CRLPERIOD)).longValue();
    }

    public void setCRLPeriod(long crlperiod) {
        data.put(CRLPERIOD, Long.valueOf(crlperiod));
    }

    public long getDeltaCRLPeriod() {
        if (data.containsKey(DELTACRLPERIOD)) {
            return ((Long) data.get(DELTACRLPERIOD)).longValue();
        } else {
            return 0;
        }
    }

    public void setDeltaCRLPeriod(long deltacrlperiod) {
        data.put(DELTACRLPERIOD, Long.valueOf(deltacrlperiod));
    }

    
    public long getCRLIssueInterval() {
        return ((Long) data.get(CRLISSUEINTERVAL)).longValue();
    }

    public void setCRLIssueInterval(long crlIssueInterval) {
        data.put(CRLISSUEINTERVAL, Long.valueOf(crlIssueInterval));
    }

    public long getCRLOverlapTime() {
        return ((Long) data.get(CRLOVERLAPTIME)).longValue();
    }

    public void setCRLOverlapTime(long crlOverlapTime) {
        data.put(CRLOVERLAPTIME, Long.valueOf(crlOverlapTime));
    }
    
    public int getDefaultCertificateProfileId() {
        Integer defaultCertificateProfileId = (Integer) data.get(DEFAULTCERTIFICATEPROFILEID);
        if (defaultCertificateProfileId != null) {
            return defaultCertificateProfileId.intValue();
        } else {
            return 0;
        }
    }
    
    private void createExtendedCAService(ExtendedCAServiceInfo info) {
        // Create implementation using reflection
        try {
            Class<?> implClass = Class.forName(info.getImplClass());
            final ExtendedCAService service = (ExtendedCAService) implClass.getConstructor(ExtendedCAServiceInfo.class).newInstance(
                    new Object[] { info });
            setExtendedCAService(service);
        } catch (ClassNotFoundException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (IllegalArgumentException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (SecurityException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (InstantiationException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (IllegalAccessException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (InvocationTargetException e) {
            log.warn("failed to add extended CA service: ", e);
        } catch (NoSuchMethodException e) {
            log.warn("failed to add extended CA service: ", e);
        }
    }
    
    /**
     * Method used to perform the service.
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    public ExtendedCAServiceResponse extendedService(CryptoToken cryptoToken, ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException,
            IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CertificateEncodingException, CertificateException, OperatorCreationException {
        ExtendedCAService service = getExtendedCAService(request.getServiceType());
        if (service == null) {
            final String msg = "Extended CA service is null for service request: "+request.getClass().getName();
            log.error(msg);
            throw new IllegalExtendedCAServiceRequestException();
        }
        // Enrich request with CA in order for the service to be able to use CA keys and certificates
        service.setCA((CABase)this);
        return service.extendedService(cryptoToken, request);
    }
    
    // Methods used with extended services
    /**
     * Initializes the ExtendedCAService
     *
     * @param cryptoToken the cryptotoken used to initiate the service
     * @param type the type of the extended key service
     * @param ca the CA used to initiate the service
     * @param cceConfig containing a list of available custom certificate extensions
     */
    @Override
    public void initExtendedService(CryptoToken cryptoToken, int type, CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
        ExtendedCAService service = getExtendedCAService(type);
        if (service != null) {
            service.init(cryptoToken, ca, cceConfig);
            setExtendedCAService(service);
        }
    }
    
    private void setFinishUser(boolean finishuser) {
        putBoolean(FINISHUSER, finishuser);
    }
    
    protected void setIncludeInHealthCheck(boolean includeInHealthCheck) {
        putBoolean(INCLUDEINHEALTHCHECK, includeInHealthCheck);
    }


    private void setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
        putBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, doEnforceUniquePublicKeys);
    }
    
    private void setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
        putBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, doEnforceUniqueDistinguishedName);
    }
    
    private void setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
        putBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, doEnforceUniqueSubjectDNSerialnumber);
    }
    
    private void setUseCertReqHistory(boolean useCertReqHistory) {
        putBoolean(USE_CERTREQ_HISTORY, useCertReqHistory);
    }
    
    private void setUseUserStorage(boolean useUserStorage) {
        putBoolean(USE_USER_STORAGE, useUserStorage);
    }
    
    private void setUseCertificateStorage(boolean useCertificateStorage) {
        putBoolean(USE_CERTIFICATE_STORAGE, useCertificateStorage);
    }

    private void setAcceptRevocationNonExistingEntry(boolean acceptRevocationNonExistingEntry) {
        putBoolean(ACCEPT_REVOCATION_NONEXISTING_ENTRY, acceptRevocationNonExistingEntry);
    }
    
    public CABase(HashMap<Object, Object> data) {
        init(data);
    }

    protected boolean getFinishUser() {
        return getBoolean(FINISHUSER, true);
    }

    protected boolean getIncludeInHealthCheck() {
        return getBoolean(INCLUDEINHEALTHCHECK, true);
    }

    public boolean isDoEnforceUniquePublicKeys() {
        return getBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, false);
    }

    public boolean isDoEnforceUniqueDistinguishedName() {
        return getBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, false);
    }

    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return getBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, false);
    }

    /**
     * Whether certificate request history should be used or not. The default value here is
     * used when the value is missing in the database, and is true for compatibility with
     * old CAs since it was not configurable and always enabled before 3.10.4.
     * For new CAs the default value is set in the web or CLI code and is false since 6.0.0.
     */
    public boolean isUseCertReqHistory() {
        return getBoolean(USE_CERTREQ_HISTORY, true);
    }
    
    /** whether issued certificates should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseCertificateStorage() {
        return getBoolean(USE_CERTIFICATE_STORAGE, true);
    }
    
    /** whether revocations for non existing entry accepted */
    public boolean isAcceptRevocationNonExistingEntry() {
        return getBoolean(ACCEPT_REVOCATION_NONEXISTING_ENTRY, false);
    }

    public boolean getKeepExpiredCertsOnCRL() {
        if(data.containsKey(KEEPEXPIREDCERTSONCRL)) {
            return ((Boolean)data.get(KEEPEXPIREDCERTSONCRL)).booleanValue();
        } else {
            return false;
        }
    }

    public void setKeepExpiredCertsOnCRL(boolean keepexpiredcertsoncrl) {
        data.put(KEEPEXPIREDCERTSONCRL, Boolean.valueOf(keepexpiredcertsoncrl));
    }
    
    /** whether users should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseUserStorage() {
        return getBoolean(USE_USER_STORAGE, true);
    }


    /**
     *
     * @param publicKey provided public key. Will not have any precedence over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     * @param notBefore null or a custom date to use as notBefore date
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param encodedValidity requested validity as SimpleTime string or ISO8601 date string (see ValidityDate.java).
     * @param certProfile
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @param cceConfig containing a list of available custom certificate extensions
     * @return The newly created certificate
     * @throws Exception
     */
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicKey publicKey, int keyusage, Date notBefore,
            String encodedValidity, CertificateProfile certProfile, String sequence, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws Exception {
        // Calculate the notAfter date
        if (notBefore == null) {
            notBefore = new Date();
        }
        final Date notAfter;
        if (StringUtils.isNotBlank(encodedValidity)) {
            notAfter = ValidityDate.getDate(encodedValidity, notBefore);
        } else {
            notAfter = null;
        }
        return generateCertificate(cryptoToken, subject, null, publicKey, keyusage, notBefore, notAfter, certProfile, null, sequence, null,
                cceConfig);
    }

    /**
     *
     * @param cryptoToken
     * @param request provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
     * publicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the
     *            profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @param certGenParams Extra parameters for certificate generation, e.g. for the CT extension. May contain references to session beans.
     * @param cceConfig containing a list of available custom certificate extensions
     * @return the generated certificate
     *
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws CertificateExtensionException  if any of the certificate extensions were invalid
     * @throws CertificateCreateException if an error occurred when trying to create a certificate.
     * @throws OperatorCreationException  if CA's private key contained an unknown algorithm or provider
     * @throws IllegalNameException if the name specified in the certificate request contains illegal characters
     * @throws IllegalValidityException  if validity was invalid
     * @throws InvalidAlgorithmException  if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
     * @throws CAOfflineException if the CA wasn't active
     * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
     * @throws IllegalKeyException if the using public key is not allowed to be used by specified certProfile
     */
    public abstract Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request,
            PublicKey publicKey, int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;

    /**
     *
     * @param request provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Can be null. Its public key is going to be used if
     * publicKey == null && subject.extendedInformation.certificateRequest == null
     * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     */
    public final Certificate generateCertificate(CryptoToken cryptoToken, final EndEntityInformation subject, final RequestMessage request,
            final PublicKey publicKey, final int keyusage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile,
            final Extensions extensions, final String sequence, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        return generateCertificate(cryptoToken, subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence, null,
                cceConfig);
    }

    public abstract X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber) throws Exception;

    public abstract X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber)
            throws Exception;

    /**
     * Create a signed PKCS#7 / CMS message.
     *
     * @param cryptoToken
     * @param cert
     * @param includeChain
     * @return A DER-encoded PKCS#7
     * @throws SignRequestSignatureException if the certificate doesn't seem to be signed by this CA
     * @see CertTools#createCertsOnlyCMS(List) for how to craete a certs-only PKCS7/CMS
     */
    public abstract byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException;

    /**
     * Creates a roll over PKCS7 for the next CA certificate, signed with the current CA key. Used by ScepServlet.
     *
     * @return Encoded signed certificate chain, suitable for use in SCEP.
     */
    public abstract byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException;

    /**
     * Creates a certificate signature request (CSR), that can be sent to an external Root CA. Request format can vary depending on the type of CA. For
     * X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are created.
     *
     * @param attributes PKCS10 attributes to be included in the request, a Collection of ASN1Encodable objects, ready to put in the request. Can be
     *            null.
     * @param signAlg the signature algorithm used by the CA
     * @param cacert the CAcertficate the request is targeted for, may be used or ignored by implementation depending on the request type created.
     * @param signatureKeyPurpose which CA token key pair should be used to create the request, normally SecConst.CAKEYPURPOSE_CERTSIGN but can also
     *            be SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
     * @param certificateProfile Certificate profile to use for CA-type specific purposes, such as CV Certificate Extensions.
     * @param cceConfig containing a list of available custom certificate extensions
     * @return byte array with binary encoded request
     * @throws CryptoTokenOfflineException if the crypto token is offline
     * @throws CertificateExtensionException if there was a problem constructing a certificate extension.
     */
    public abstract byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert,
            int signatureKeyPurpose, CertificateProfile certificateProfile, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CertificateExtensionException;

    public abstract byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException;

}
