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
import java.util.Objects;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidator;
import org.bouncycastle.jce.provider.PKIXNameConstraintValidatorException;
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
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;

/**
 * CA is a base class that should be inherited by all CA types
 */
public abstract class CABase extends CABaseCommon implements Serializable, CA {

    private static final long serialVersionUID = -8755429830955594642L;

    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Log4j instance */
    private static Logger log = Logger.getLogger(CABase.class);
    /** Internal localization of logs and errors */

    // protected fields.
    private static final String FINISHUSER = "finishuser";

    private static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = "doEnforceUniquePublicKeys";
    private static final String DO_ENFORCE_KEY_RENEWAL = "doEnforceKeyRenewal";
    private static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = "doEnforceUniqueDistinguishedName";
    private static final String DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER = "doEnforceUniqueSubjectDNSerialnumber";
    private static final String USE_CERTREQ_HISTORY = "useCertreqHistory";
    private static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";
    private static final String ACCEPT_REVOCATION_NONEXISTING_ENTRY = "acceptRevocationNonExistingEntry";
    private static final String KEEPEXPIREDCERTSONCRL = "keepExpiredCertsOnCRL";

    protected static final String INCLUDEINHEALTHCHECK = "includeinhealthcheck";
    private static final String USE_USER_STORAGE = "useUserStorage";

    /** No args constructor required for ServiceLocator */
    protected CABase() {
    }

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public CABase(CAInfo cainfo) {
        init(cainfo);
    }

    @Override
    public void init(CAInfo cainfo) {
        data = new LinkedHashMap<>();
        super.init(cainfo);
        data.put(USENOCONFLICTCERTIFICATEDATA, cainfo.isUseNoConflictCertificateData());
        if (!cainfo.isUseCertificateStorage()) {
            data.put(DEFAULTCERTIFICATEPROFILEID, cainfo.getDefaultCertificateProfileId());
        }
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceKeyRenewal(cainfo.isDoEnforceKeyRenewal());
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
        setGenerateCrlUponRevocation(cainfo.isGenerateCrlUponRevocation());
        setAllowChangingRevocationReason(cainfo.isAllowChangingRevocationReason());

        List<Integer> extendedservicetypes = new ArrayList<>();
        if (cainfo.getExtendedCAServiceInfos() != null) {
            for(ExtendedCAServiceInfo next : cainfo.getExtendedCAServiceInfos()) {
                createExtendedCAService(next);
                if (log.isDebugEnabled()) {
                    log.debug("Adding extended service to CA '"+cainfo.getName()+"': "+next.getType()+", "+next.getImplClass());
                }
                extendedservicetypes.add(next.getType());
            }
        }
        data.put(EXTENDEDCASERVICES, extendedservicetypes);
        setApprovals(cainfo.getApprovals());
    }

    /** Constructor used when retrieving existing CA from database. */
    @Override
    public void init(HashMap<Object, Object> loadedData) {
        super.init(loadedData);
    }

    @Override
    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        super.updateCA(cryptoToken, cainfo, cceConfig);
        data.put(CRLPERIOD, cainfo.getCRLPeriod());
        data.put(DELTACRLPERIOD, cainfo.getDeltaCRLPeriod());
        data.put(GENERATECRLUPONREVOCATION, cainfo.isGenerateCrlUponRevocation());
        data.put(ALLOWCHANGINGREVOCATIONREASON, cainfo.isAllowChangingRevocationReason());
        data.put(CRLISSUEINTERVAL, cainfo.getCRLIssueInterval());
        data.put(CRLOVERLAPTIME, cainfo.getCRLOverlapTime());
        data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
        data.put(VALIDATORS, cainfo.getValidators());
        data.put(USENOCONFLICTCERTIFICATEDATA, cainfo.isUseNoConflictCertificateData());
        if (cainfo.getDefaultCertificateProfileId() > 0 && !cainfo.isUseCertificateStorage()) {
            data.put(DEFAULTCERTIFICATEPROFILEID, cainfo.getDefaultCertificateProfileId());
        }
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL());
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceKeyRenewal(cainfo.isDoEnforceKeyRenewal());
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
                    service.update(cryptoToken, info, this, cceConfig); // the service's signing certificate might get created at this point!
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

    @Override
    public long getCRLPeriod() {
        return (long) data.get(CRLPERIOD);
    }

    @Override
    public void setCRLPeriod(long crlperiod) {
        data.put(CRLPERIOD, crlperiod);
    }

    @Override
    public long getDeltaCRLPeriod() {
        if (data.containsKey(DELTACRLPERIOD)) {
            return (long) data.get(DELTACRLPERIOD);
        }
        return 0;
    }

    @Override
    public void setDeltaCRLPeriod(long deltacrlperiod) {
        data.put(DELTACRLPERIOD, deltacrlperiod);
    }
    
    @Override
    public boolean getGenerateCrlUponRevocation() {
        return getBoolean(GENERATECRLUPONREVOCATION, false);
    }

    @Override
    public void setGenerateCrlUponRevocation(boolean generate) {
        data.put(GENERATECRLUPONREVOCATION, generate);
    }

    @Override
    public boolean getAllowChangingRevocationReason() {
        return getBoolean(ALLOWCHANGINGREVOCATIONREASON, false);
    }

    @Override
    public void setAllowChangingRevocationReason(boolean allow) {
        data.put(ALLOWCHANGINGREVOCATIONREASON, allow);
    }

    @Override
    public long getCRLIssueInterval() {
        return (long) data.get(CRLISSUEINTERVAL);
    }

    @Override
    public void setCRLIssueInterval(long crlIssueInterval) {
        data.put(CRLISSUEINTERVAL, crlIssueInterval);
    }

    @Override
    public long getCRLOverlapTime() {
        return (long) data.get(CRLOVERLAPTIME);
    }

    @Override
    public void setCRLOverlapTime(long crlOverlapTime) {
        data.put(CRLOVERLAPTIME, crlOverlapTime);
    }

    @Override
    public int getDefaultCertificateProfileId() {
        Integer defaultCertificateProfileId = (Integer) data.get(DEFAULTCERTIFICATEPROFILEID);
        if (defaultCertificateProfileId != null) {
            return defaultCertificateProfileId;
        }
        return 0;
    }
    
    private void createExtendedCAService(ExtendedCAServiceInfo info) {
        // Create implementation using reflection
        try {
            Class<?> implClass = Class.forName(info.getImplClass());
            final ExtendedCAService service = (ExtendedCAService) implClass.getConstructor(ExtendedCAServiceInfo.class).newInstance(info);
            setExtendedCAService(service);
        } catch (ReflectiveOperationException | IllegalArgumentException | SecurityException e) {
            log.warn("failed to add extended CA service: ", e);
        }
    }
    
    /**
     * Method used to perform the service.
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws CertificateEncodingException
     */
    @Override
    public ExtendedCAServiceResponse extendedService(CryptoToken cryptoToken, ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException,
            IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, CertificateException, OperatorCreationException {
        ExtendedCAService service = getExtendedCAService(request.getServiceType());
        if (service == null) {
            final String msg = "Extended CA service is null for service request: "+request.getClass().getName();
            log.error(msg);
            throw new IllegalExtendedCAServiceRequestException(msg);
        }
        // Enrich request with CA in order for the service to be able to use CA keys and certificates
        service.setCA(this);
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
    private void setDoEnforceKeyRenewal(boolean doEnforceKeyRenewal) {
        putBoolean(DO_ENFORCE_KEY_RENEWAL, doEnforceKeyRenewal);
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

    @Override
    public boolean isDoEnforceUniquePublicKeys() {
        return getBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, false);
    }

    @Override
    public boolean isDoEnforceKeyRenewal() {
        return getBoolean(DO_ENFORCE_KEY_RENEWAL, false);
    }

    @Override
    public boolean isDoEnforceUniqueDistinguishedName() {
        return getBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, false);
    }

    @Override
    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return getBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, false);
    }

    /**
     * Whether certificate request history should be used or not. The default value here is
     * used when the value is missing in the database, and is true for compatibility with
     * old CAs since it was not configurable and always enabled before 3.10.4.
     * For new CAs the default value is set in the web or CLI code and is false since 6.0.0.
     */
    @Override
    public boolean isUseCertReqHistory() {
        return getBoolean(USE_CERTREQ_HISTORY, true);
    }

    @Override
    /** whether issued certificates should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseCertificateStorage() {
        return getBoolean(USE_CERTIFICATE_STORAGE, true);
    }

    @Override
    /** whether revocations for non existing entry accepted */
    public boolean isAcceptRevocationNonExistingEntry() {
        return getBoolean(ACCEPT_REVOCATION_NONEXISTING_ENTRY, false);
    }

    @Override
    public boolean getKeepExpiredCertsOnCRL() {
        return getBoolean(KEEPEXPIREDCERTSONCRL, false);
    }

    @Override
    public void setKeepExpiredCertsOnCRL(boolean keepexpiredcertsoncrl) {
        data.put(KEEPEXPIREDCERTSONCRL, keepexpiredcertsoncrl);
    }
    
    /** whether users should be stored or not, default true as was the case before 3.10.x */
    @Override
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
     */
    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicKey publicKey, int keyusage, Date notBefore,
            String encodedValidity, CertificateProfile certProfile, String sequence, AvailableCustomCertificateExtensionsConfiguration cceConfig) throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException, OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException {
        // Calculate the notAfter date
        if (notBefore == null) {
            notBefore = new Date();
        }
        final Date notAfter;
        if (StringUtils.isNotBlank(encodedValidity)) {
            notAfter = ValidityDate.getDate(encodedValidity, notBefore, getCAInfo().isExpirationInclusive());
        } else {
            notAfter = null;
        }
        return generateCertificate(cryptoToken, subject, null, publicKey, keyusage, notBefore, notAfter, certProfile, null, sequence, null,
                cceConfig);
    }

    /**
     *
     * @param request provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Can be null. Its public key is going to be used if
     * publicKey == null && subject.extendedInformation.certificateRequest == null
     * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     */
    @Override
    public final Certificate generateCertificate(CryptoToken cryptoToken, final EndEntityInformation subject, final RequestMessage request,
            final PublicKey publicKey, final int keyusage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile,
            final Extensions extensions, final String sequence, final AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        return generateCertificate(cryptoToken, subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence, null,
                cceConfig);
    }
    
    /**
     * Checks that the given SubjectDN / SAN satisfies the Name Constraints of the given issuer (if there are any).
     * This method checks the Name Constraints in the given issuer only. A complete implementation of
     * name constraints should check the whole certificate chain.
     * 
     * @param subjectDNName Subject DN to check. Optional.
     * @param subjectAltName Subject Alternative Name to check. Optional.
     * @throws IllegalNameException if the name(s) didn't pass naming constraints 
     */
    public static void checkNameConstraints(final X509Certificate issuer, final X500Name subjectDNName, final GeneralNames subjectAltName) throws IllegalNameException {
        final byte[] ncbytes = issuer.getExtensionValue(Extension.nameConstraints.getId());
        final ASN1OctetString ncstr = (ncbytes != null ? ASN1OctetString.getInstance(ncbytes) : null);
        final ASN1Sequence ncseq = (ncbytes != null ? ASN1Sequence.getInstance(ncstr.getOctets()) : null);
        final NameConstraints nc = (ncseq != null ? NameConstraints.getInstance(ncseq) : null);
        if (nc != null) {
            if (subjectDNName != null) {
                // Skip check for root CAs
                final X500Name issuerDNName = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
                if (issuerDNName.equals(subjectDNName)) {
                    if (log.isTraceEnabled()) {
                        log.trace("Skipping test for Root CA: " + subjectDNName);
                    }
                    return;
                }
            }
                  
            final PKIXNameConstraintValidator validator = new PKIXNameConstraintValidator();
            
            GeneralSubtree[] permitted = nc.getPermittedSubtrees();
            GeneralSubtree[] excluded = nc.getExcludedSubtrees();
                        
            if (permitted != null) {
                
                GeneralSubtree[] permittedFormatted = new GeneralSubtree[permitted.length];
                
                for (int i = 0; i < permitted.length; i++) {
                    GeneralSubtree subtree = permitted[i];
                    log.trace("Permitted subtree: " + subtree.getBase());
                    log.trace(ASN1Dump.dumpAsString(subtree.getBase()));
                    
                    if(subtree.getBase().getTagNo() != GeneralName.uniformResourceIdentifier) {
                        permittedFormatted[i] = subtree;
                    } else {
                        String uri = subtree.getBase().getName().toString();
                        String host = extractHostFromURL(uri);
                        permittedFormatted[i] = new GeneralSubtree(
                                    new GeneralName(GeneralName.uniformResourceIdentifier, host));
                    }
                }
            
                validator.intersectPermittedSubtree(permittedFormatted);
            }
        
            if (excluded != null) {
                for (GeneralSubtree subtree : excluded) {
                    if (log.isTraceEnabled()) {
                        log.trace("Excluded subtree: " + subtree.getBase());
                        log.trace(ASN1Dump.dumpAsString(subtree.getBase()));
                    }
                    if(subtree.getBase().getTagNo() != GeneralName.uniformResourceIdentifier) {
                        validator.addExcludedSubtree(subtree);
                    } else {
                        String uri = subtree.getBase().getName().toString();
                        String host = extractHostFromURL(uri);
                        validator.addExcludedSubtree(new GeneralSubtree(
                                    new GeneralName(GeneralName.uniformResourceIdentifier, host)));
                    }
                }
            }

            if (subjectDNName != null) {
                GeneralName dngn = new GeneralName(subjectDNName);
                try {
                    validator.checkPermitted(dngn);
                    validator.checkExcluded(dngn);
                } catch (PKIXNameConstraintValidatorException e) {
                    final String dnStr = subjectDNName.toString();
                    final boolean isLdapOrder = CertTools.dnHasMultipleComponents(dnStr) && !CertTools.isDNReversed(dnStr);
                    if (isLdapOrder) {
                        final String msg = intres.getLocalizedMessage("nameconstraints.x500dnorderrequired");
                        throw new IllegalNameException(msg);
                    } else {
                        final String msg = intres.getLocalizedMessage("nameconstraints.forbiddensubjectdn", subjectDNName);
                        throw new IllegalNameException(msg, e);
                    }
                }
            }
            
            if (subjectAltName != null) {
                for (GeneralName sangn : subjectAltName.getNames()) {
                    try {
                        validator.checkPermitted(sangn);
                        if (sangn.getTagNo() == 2 && isAllDNSNamesExcluded(excluded)) {
                            final String msg = intres.getLocalizedMessage("nameconstraints.forbiddensubjectaltname",
                                    NameConstraint.getNameConstraintFromType(sangn.getTagNo()) + ":" + sangn.toString().substring(2));
                            throw new IllegalNameException(msg);
                        }
                        validator.checkExcluded(sangn);
                    } catch (PKIXNameConstraintValidatorException e) {
                        final String msg = intres.getLocalizedMessage("nameconstraints.forbiddensubjectaltname",
                                NameConstraint.getNameConstraintFromType(sangn.getTagNo()) + ":" + sangn.toString().substring(2));
                        throw new IllegalNameException(msg, e);
                    }
                }
            }
        }
    }
    
    // Check if we should exclude all dns names
    private static boolean isAllDNSNamesExcluded(GeneralSubtree[] excluded) {
        if (Objects.isNull(excluded)) {
            return false;
        }
        
        for (int i = 0; i < excluded.length; i++) {
            if (excluded[i].getBase().toString().equals("2: ")) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Refers private method from org.bouncycastle.asn1.x509.PKIXNameConstraintValidator.
     * It is used here to extract host from name constraint in CA. Bouncy Castle extracts host
     * from the URIs in subjectDN or subjectAlternativeName.
     * 
     * @param url
     * @return
     */
    private static String extractHostFromURL(String url) {
        // see RFC 1738
        // remove ':' after protocol, e.g. https:
        String sub = url.substring(url.indexOf(':') + 1);
        // extract host from Common Internet Scheme Syntax, e.g. https://
        if (sub.indexOf("//") != -1) {
            sub = sub.substring(sub.indexOf("//") + 2);
        }
        // first remove port, e.g. https://test.com:21
        if (sub.lastIndexOf(':') != -1) {
            sub = sub.substring(0, sub.lastIndexOf(':'));
        }
        // remove user and password, e.g. https://john:password@test.com
        sub = sub.substring(sub.indexOf(':') + 1);
        sub = sub.substring(sub.indexOf('@') + 1);
        // remove local parts, e.g. https://test.com/bla
        if (sub.indexOf('/') != -1) {
            sub = sub.substring(0, sub.indexOf('/'));
        }
        return sub;
    }

}
