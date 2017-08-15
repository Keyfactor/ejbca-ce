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

import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.catoken.CAToken;
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
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

/**
 * CA is a base class that should be inherited by all CA types
 * 
 * @version $Id$
 */
public abstract class CA extends UpgradeableDataHashMap implements Serializable {

    private static final long serialVersionUID = -8755429830955594642L;

    /** Log4j instance */
    private static Logger log = Logger.getLogger(CA.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    // protected fields.
    public static final String CATYPE = "catype";
    protected static final String SUBJECTDN = "subjectdn";
    protected static final String CAID = "caid";
    public static final String NAME = "name";
    @Deprecated
    protected static final String VALIDITY = "validity";
    protected static final String ENCODED_VALIDITY = "encodedvalidity";
    protected static final String EXPIRETIME = "expiretime";
    protected static final String CERTIFICATECHAIN = "certificatechain";
    protected static final String RENEWEDCERTIFICATECHAIN = "renewedcertificatechain";
    protected static final String ROLLOVERCERTIFICATECHAIN = "rollovercertificatechain";
    public static final String CATOKENDATA = "catoken";
    protected static final String SIGNEDBY = "signedby";
    protected static final String DESCRIPTION = "description";
    protected static final String REVOCATIONREASON = "revokationreason";
    protected static final String REVOCATIONDATE = "revokationdate";
    protected static final String CERTIFICATEPROFILEID = "certificateprofileid";
    protected static final String CRLPERIOD = "crlperiod";
    protected static final String DELTACRLPERIOD = "deltacrlperiod";
    protected static final String CRLISSUEINTERVAL = "crlIssueInterval";
    protected static final String CRLOVERLAPTIME = "crlOverlapTime";
    protected static final String CRLPUBLISHERS = "crlpublishers";
    protected static final String VALIDATORS = "keyvalidators";
    private static final String FINISHUSER = "finishuser";
    protected static final String REQUESTCERTCHAIN = "requestcertchain";
    protected static final String EXTENDEDCASERVICES = "extendedcaservices";
    protected static final String EXTENDEDCASERVICE = "extendedcaservice";
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
    /**
     * @deprecated since 6.8.0, replaced by the approvals Action:ApprovalProfile mapping
     */
    @Deprecated
    protected static final String APPROVALPROFILE = "approvalprofile";
    protected static final String INCLUDEINHEALTHCHECK = "includeinhealthcheck";
    private static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = "doEnforceUniquePublicKeys";
    private static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = "doEnforceUniqueDistinguishedName";
    private static final String DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER = "doEnforceUniqueSubjectDNSerialnumber";
    private static final String USE_CERTREQ_HISTORY = "useCertreqHistory";
    private static final String USE_USER_STORAGE = "useUserStorage";
    private static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";
    private static final String LATESTLINKCERTIFICATE = "latestLinkCertificate";
    private static final String KEEPEXPIREDCERTSONCRL = "keepExpiredCertsOnCRL";
    private static final String APPROVALS = "approvals";

    private HashMap<Integer, ExtendedCAService> extendedcaservicemap = new HashMap<Integer, ExtendedCAService>();

    private ArrayList<Certificate> certificatechain = null;
    private ArrayList<Certificate> renewedcertificatechain = null;
    private ArrayList<Certificate> requestcertchain = null;

    private CAInfo cainfo = null;
    private CAToken caToken = null;

    /** No args constructor required for ServiceLocator */
    protected CA() {}
    
    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public CA(CAInfo cainfo) {
        init(cainfo);
    }
    public void init(CAInfo cainfo) {
        data = new LinkedHashMap<Object, Object>();

        this.cainfo = cainfo;

        setEncodedValidity(cainfo.getEncodedValidity());
        setSignedBy(cainfo.getSignedBy());
        data.put(DESCRIPTION, cainfo.getDescription());
        data.put(REVOCATIONREASON, Integer.valueOf(-1));
        data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL()); 
        setCRLPeriod(cainfo.getCRLPeriod());
        setCRLIssueInterval(cainfo.getCRLIssueInterval());
        setCRLOverlapTime(cainfo.getCRLOverlapTime());
        setDeltaCRLPeriod(cainfo.getDeltaCRLPeriod());
        setCRLPublishers(cainfo.getCRLPublishers());
        setValidators(cainfo.getValidators());
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName());
        setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        setUseCertReqHistory(cainfo.isUseCertReqHistory());
        setUseUserStorage(cainfo.isUseUserStorage());
        setUseCertificateStorage(cainfo.isUseCertificateStorage());

        ArrayList<Integer> extendedservicetypes = new ArrayList<Integer>();
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

    public CA(HashMap<Object, Object> data) {
        init(data);
    }

    /** Constructor used when retrieving existing CA from database. */
    public void init(HashMap<Object, Object> data) {
        loadData(data);
        extendedcaservicemap = new HashMap<Integer, ExtendedCAService>();
    }

    public void setCAInfo(CAInfo cainfo) {
        this.cainfo = cainfo;
    }

    public CAInfo getCAInfo() {
        return this.cainfo;
    }

    public String getSubjectDN() {
        return cainfo.getSubjectDN();
    }

    public void setSubjectDN(String subjectdn) {
        cainfo.subjectdn = subjectdn;
    }

    public int getCAId() {
        return cainfo.getCAId();
    }

    public void setCAId(int caid) {
        cainfo.caid = caid;
    }

    public String getName() {
        return cainfo.getName();
    }

    public void setName(String caname) {
        cainfo.name = caname;
    }

    public int getStatus() {
        return cainfo.getStatus();
    }

    public void setStatus(int status) {
        cainfo.status = status;
    }

    /**
     * @return one of CAInfo.CATYPE_CVC or CATYPE_X509
     */
    public int getCAType() {
        return ((Integer) data.get(CATYPE)).intValue();
    }

    @Deprecated
    public long getValidity() {
        return ((Number) data.get(VALIDITY)).longValue();
    }
    
    /**
     * Gets the validity.
     * @return the validity as ISO8601 date or relative time.
     * @See {@link org.cesecore.util.ValidityDate ValidityDate}
     */
    @SuppressWarnings("deprecation")
    public String getEncodedValidity() {
        String result = (String) data.get(ENCODED_VALIDITY);
        if (StringUtils.isBlank(result)) {
            result = ValidityDate.getStringBeforeVersion661(getValidity());
        }
        return result;
    }

    /**
     * Sets the validity as relative time (format '*y *mo *d *h *m *s', i.e. '1y +2mo -3d 4h 5m 6s') or as fixed end date 
     * (ISO8601 format, i.e. 'yyyy-MM-dd HH:mm:ssZZ', 'yyyy-MM-dd HH:mmZZ' or 'yyyy-MM-ddZZ' with optional '+00:00' appended).
     *
     * @param encodedValidity
     */
    public void setEncodedValidity(String encodedValidity) {
        data.put(ENCODED_VALIDITY, encodedValidity);
    }

    public Date getExpireTime() {
        return ((Date) data.get(EXPIRETIME));
    }

    public void setExpireTime(Date expiretime) {
        data.put(EXPIRETIME, expiretime);
    }

    public int getSignedBy() {
        return ((Integer) data.get(SIGNEDBY)).intValue();
    }

    public void setSignedBy(int signedby) {
        data.put(SIGNEDBY, Integer.valueOf(signedby));
    }

    public String getDescription() {
        return ((String) data.get(DESCRIPTION));
    }

    public void setDescription(String description) {
        data.put(DESCRIPTION, description);
    }

    public int getRevocationReason() {
        return ((Integer) data.get(REVOCATIONREASON)).intValue();
    }

    public void setRevocationReason(int reason) {
        data.put(REVOCATIONREASON, Integer.valueOf(reason));
    }

    public Date getRevocationDate() {
        return (Date) data.get(REVOCATIONDATE);
    }

    public void setRevocationDate(Date date) {
        data.put(REVOCATIONDATE, date);
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

    @SuppressWarnings("unchecked")
    public Collection<Integer> getCRLPublishers() {
        return ((Collection<Integer>) data.get(CRLPUBLISHERS));
    }

    public void setCRLPublishers(Collection<Integer> crlpublishers) {
        data.put(CRLPUBLISHERS, crlpublishers);
    }

    @SuppressWarnings("unchecked")
    public Collection<Integer> getValidators() {
        return ((Collection<Integer>) data.get(VALIDATORS));
    }

    public void setValidators(Collection<Integer> validators) {
        data.put(VALIDATORS, validators);
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
        
    public int getCertificateProfileId() {
        return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();
    }

    /** @return the CAs token reference. */
    public CAToken getCAToken() {
        if (caToken == null) {
            @SuppressWarnings("unchecked")
            HashMap<String, String> tokendata = (HashMap<String, String>) data.get(CATOKENDATA);
            final CAToken ret = new CAToken(tokendata);
            String signaturealg = tokendata.get(CAToken.SIGNATUREALGORITHM);
            String encryptionalg = tokendata.get(CAToken.ENCRYPTIONALGORITHM);
            String keysequence = CAToken.DEFAULT_KEYSEQUENCE;
            Object seqo = tokendata.get(CAToken.SEQUENCE);
            if (seqo != null) {
                keysequence = (String)seqo;             
            }
            int keysequenceformat = StringTools.KEY_SEQUENCE_FORMAT_NUMERIC;
            Object seqfo = tokendata.get(CAToken.SEQUENCE_FORMAT);
            if (seqfo != null) {
                keysequenceformat = (Integer)seqfo;             
            }
            // Set values for new CA token
            ret.setSignatureAlgorithm(signaturealg);
            ret.setEncryptionAlgorithm(encryptionalg);
            ret.setKeySequence(keysequence);
            ret.setKeySequenceFormat(keysequenceformat);
            caToken = ret;
        }
        return caToken;
    }

    /** Sets the CA token. */
    public void setCAToken(CAToken catoken) throws InvalidAlgorithmException {
        // Check that the signature algorithm is one of the allowed ones, only check if there is a sigAlg though
    	// things like a NulLCryptoToken does not have signature algorithms
    	final String sigAlg = catoken.getSignatureAlgorithm();
    	if (StringUtils.isNotEmpty(sigAlg)) {
            if (!StringTools.containsCaseInsensitive(AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
                final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg, ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
                throw new InvalidAlgorithmException(msg);        	
            }    		
    	}
    	final String encAlg = catoken.getEncryptionAlgorithm();
    	if (StringUtils.isNotEmpty(encAlg)) {
    		if (!StringTools.containsCaseInsensitive(AlgorithmConstants.AVAILABLE_SIGALGS, encAlg)) {
    			final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", encAlg, ArrayUtils.toString(AlgorithmConstants.AVAILABLE_SIGALGS));
    			throw new InvalidAlgorithmException(msg);        	
    		}
    	}
        data.put(CATOKENDATA, catoken.saveData());
        this.caToken = catoken;
    }

    /** Returns a collection of CA certificates, or null if no request certificate chain exists */
    public Collection<Certificate> getRequestCertificateChain() {
        if (requestcertchain == null) {
            @SuppressWarnings("unchecked")
            final Collection<String> storechain = (Collection<String>) data.get(REQUESTCERTCHAIN);
            if (storechain != null) {
                this.requestcertchain = new ArrayList<Certificate>();
                for (final String b64Cert : storechain) {
                    try {
                        this.requestcertchain.add(CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()), Certificate.class));
                    } catch (CertificateParsingException e) {
                       throw new IllegalStateException("Database seems to contain invalid certificate information.", e);
                    }

                }
            }
        }
        return requestcertchain;
    }

    public void setRequestCertificateChain(Collection<Certificate> requestcertificatechain) {
        final ArrayList<String> storechain = new ArrayList<String>();
        for (final Certificate cert : requestcertificatechain) {
            try {
                storechain.add(new String(Base64.encode(cert.getEncoded())));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        data.put(REQUESTCERTCHAIN, storechain);
        this.requestcertchain = new ArrayList<Certificate>();
        this.requestcertchain.addAll(requestcertificatechain);
    }

    /**
     * Returns a collection of CA-certificates, with this CAs cert i position 0, or null if no CA-certificates exist. The root CA certificate will
     * thus be in the last position.
     * 
     * @return Collection of Certificate
     */
    public Collection<Certificate> getCertificateChain() {
        if (certificatechain == null) {
            @SuppressWarnings("unchecked")
            Collection<String> storechain = (Collection<String>) data.get(CERTIFICATECHAIN);
            if (storechain == null) {
                return null;
            }
            Iterator<String> iter = storechain.iterator();
            this.certificatechain = new ArrayList<Certificate>();
            while (iter.hasNext()) {
                String b64Cert = iter.next();
                try {
                    Certificate cert = CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()), Certificate.class);
                    if (cert != null) {
                        if (log.isDebugEnabled()) {
                            log.debug("Adding CA certificate from CERTIFICATECHAIN to certificatechain:");
                            log.debug("Cert subjectDN: " + CertTools.getSubjectDN(cert));
                            log.debug("Cert issuerDN: " + CertTools.getIssuerDN(cert));
                        }
                        this.certificatechain.add(cert);
                    } else {
                        throw new IllegalArgumentException("Can not create certificate object from: " + b64Cert);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return certificatechain;
    }

    public void setCertificateChain(final Collection<Certificate> certificatechain) {
        final ArrayList<String> storechain = new ArrayList<String>();
        for (final Certificate cert : certificatechain) {
            try {
                storechain.add(new String(Base64.encode(cert.getEncoded())));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }
        data.put(CERTIFICATECHAIN, storechain);
        this.certificatechain = new ArrayList<Certificate>(certificatechain);
        this.cainfo.setCertificateChain(certificatechain);
    }

    /**
     * @return the list of renewed CA certificates in order from the oldest as first to the newest as the last one
     */
    public List<Certificate> getRenewedCertificateChain() {
        if (renewedcertificatechain == null) {
            @SuppressWarnings("unchecked")
            Collection<String> storechain = (Collection<String>) data.get(RENEWEDCERTIFICATECHAIN);
            if (storechain == null) {
                return null;
            }
            Iterator<String> iter = storechain.iterator();
            renewedcertificatechain = new ArrayList<Certificate>();
            while (iter.hasNext()) {
                String b64Cert = iter.next();
                try {
                    Certificate cert = CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()), Certificate.class);
                    if (log.isDebugEnabled()) {
                        log.debug("Adding CA certificate from RENEWEDCERTIFICATECHAIN to renewedcertificatechain:");
                        log.debug("Cert subjectDN: " + CertTools.getSubjectDN(cert));
                        log.debug("Cert issuerDN: " + CertTools.getIssuerDN(cert));
                    }
                    renewedcertificatechain.add(cert);
                } catch (CertificateParsingException e) {
                    throw new IllegalStateException("Some certificates from renewed certificate chain could not be parsed", e);
                }
            }
        }
        return renewedcertificatechain;
    }

    /**
     * Make sure to respect the order of renewed CA certificates in the collection: from the oldest as first to the newest as the last one
     * @param certificatechain collection of the renewed CA certificates to be stored
     */
    public void setRenewedCertificateChain(final List<Certificate> certificatechain) {
        ArrayList<String> storechain = new ArrayList<String>();
        for (Certificate cert : certificatechain) {
            try {
                String b64Cert = new String(Base64.encode(cert.getEncoded()));
                storechain.add(b64Cert);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Renewed certificates could not be encoded", e);
            }
        }
        data.put(RENEWEDCERTIFICATECHAIN, storechain);

        renewedcertificatechain = new ArrayList<Certificate>();
        renewedcertificatechain.addAll(certificatechain);
        cainfo.setRenewedCertificateChain(certificatechain);
    }

    public void setRolloverCertificateChain(Collection<Certificate> certificatechain) {
        Iterator<Certificate> iter = certificatechain.iterator();
        ArrayList<String> storechain = new ArrayList<String>();
        while (iter.hasNext()) {
            Certificate cert = iter.next();
            try {
                String b64Cert = new String(Base64.encode(cert.getEncoded()));
                storechain.add(b64Cert);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        data.put(ROLLOVERCERTIFICATECHAIN, storechain);
    }

    public List<Certificate> getRolloverCertificateChain() {
        final List<?> storechain = (List<?>)data.get(ROLLOVERCERTIFICATECHAIN);
        if (storechain == null) {
            return null;
        }
        final List<Certificate> chain = new ArrayList<Certificate>(storechain.size());
        for (Object o : storechain) {
            final String b64Cert = (String)o;
            try {
                final byte[] decoded = Base64.decode(b64Cert.getBytes("US-ASCII"));
                final Certificate cert = CertTools.getCertfromByteArray(decoded, Certificate.class);
                chain.add(cert);
            } catch (UnsupportedEncodingException e) {
                throw new IllegalStateException(e);
            } catch (CertificateParsingException e) {
                throw new IllegalStateException(e);
            }
        }
        return chain;
    }

    public void clearRolloverCertificateChain() {
        data.remove(ROLLOVERCERTIFICATECHAIN);
    }

    /** Returns the CAs certificate, or null if no CA-certificates exist. */
    public Certificate getCACertificate() {
        if (certificatechain == null) {
            getCertificateChain();
            // if it's still null, return null
            if (certificatechain == null) {
                return null;
            }
        }
        if (certificatechain.size() == 0) {
            return null;
        }
        Certificate ret = (Certificate) certificatechain.get(0);
        if (log.isDebugEnabled()) {
            log.debug("CA certificate chain is " + certificatechain.size() + " levels deep.");
            log.debug("CA-cert subjectDN: " + CertTools.getSubjectDN(ret));
            log.debug("CA-cert issuerDN: " + CertTools.getIssuerDN(ret));
        }
        return ret;
    }
    
    /** Returns true if we should use the next CA certificate for rollover, instead of the current CA certificate. */
    public boolean getUseNextCACert(final RequestMessage request) {
        final Certificate currentCert = getCACertificate();
        if (request == null) {
            // We get here when creating a new CA
            log.trace("getUseNextCACert: request is null. most likely this is a new CA");
            return false;
        }
        
        final BigInteger requestSerNo = request.getSerialNo();
        if (requestSerNo == null) {
            log.debug("getUseNextCACert: No serial number in request. Will use current CA cert.");
            return false;
        }
        
        final BigInteger currentSerNo = CertTools.getSerialNumber(currentCert);
        if (currentSerNo == null || currentSerNo.equals(requestSerNo)) {
            // Normal case
            log.trace("getUseNextCACert: CA serial number matches request serial number");
            return false;
        }
        
        final List<Certificate> rolloverChain = getRolloverCertificateChain();
        if (rolloverChain == null || rolloverChain.isEmpty()) {
            log.debug("getUseNextCACert: Serial number in request does not match CA serial number, and no roll over certificate chain is present. Will use current CA cert.");
            return false;
        }
        
        final Certificate rolloverCert = rolloverChain.get(0);
        final BigInteger rolloverSerNo = CertTools.getSerialNumber(rolloverCert);
        if (rolloverSerNo != null && rolloverSerNo.equals(requestSerNo)) {
            log.debug("getUseNextCACert: Serial number in request matches next (rollover) CA cert. Using next CA cert and key.");
            return true; // this is the only case where we use the next CA cert
        }
        
        log.debug("getUseNextCACert: Serial number in request does not match CA serial number nor next (rollover) CA cert. Will use current CA cert.");
        return false;
    }

    protected boolean getFinishUser() {
        return getBoolean(FINISHUSER, true);
    }

    private void setFinishUser(boolean finishuser) {
        putBoolean(FINISHUSER, finishuser);
    }

    protected boolean getIncludeInHealthCheck() {
        return getBoolean(INCLUDEINHEALTHCHECK, true);
    }

    protected void setIncludeInHealthCheck(boolean includeInHealthCheck) {
        putBoolean(INCLUDEINHEALTHCHECK, includeInHealthCheck);
    }

    public boolean isDoEnforceUniquePublicKeys() {
        return getBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, false);
    }

    private void setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
        putBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, doEnforceUniquePublicKeys);
    }

    public boolean isDoEnforceUniqueDistinguishedName() {
        return getBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, false);
    }

    private void setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
        putBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, doEnforceUniqueDistinguishedName);
    }

    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return getBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, false);
    }

    private void setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
        putBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, doEnforceUniqueSubjectDNSerialnumber);
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

    private void setUseCertReqHistory(boolean useCertReqHistory) {
        putBoolean(USE_CERTREQ_HISTORY, useCertReqHistory);
    }

    /** whether users should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseUserStorage() {
        return getBoolean(USE_USER_STORAGE, true);
    }

    private void setUseUserStorage(boolean useUserStorage) {
        putBoolean(USE_USER_STORAGE, useUserStorage);
    }

    /** whether issued certificates should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseCertificateStorage() {
        return getBoolean(USE_CERTIFICATE_STORAGE, true);
    }

    private void setUseCertificateStorage(boolean useCertificateStorage) {
        putBoolean(USE_CERTIFICATE_STORAGE, useCertificateStorage);
    }

    /**
     * @return A 1:1 mapping between Approval Action:Approval Profile ID
     */
    @SuppressWarnings("unchecked")
    public Map<ApprovalRequestType, Integer> getApprovals() {
        return (Map<ApprovalRequestType, Integer>) data.get(APPROVALS);
    }
    
    public void setApprovals(Map<ApprovalRequestType, Integer> approvals) {
        // We must store this as a predictable order map in the database, in order for databaseprotection to work
        if(approvals == null) {
            approvals = new LinkedHashMap<>();
        }
        data.put(APPROVALS, new LinkedHashMap<ApprovalRequestType, Integer>(approvals));
    }
    
    /**
     * @return a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals,
     * default none and never null.
     * 
     * @deprecated since 6.8.0, see getApprovals()
     */
    @SuppressWarnings("unchecked")
    public Collection<Integer> getApprovalSettings() {
        if (data.get(APPROVALSETTINGS) == null) {
            return new ArrayList<Integer>();
        }
        return (Collection<Integer>) data.get(APPROVALSETTINGS);
    }

    /**
     * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals
     * 
     * @deprecated since 6.8.0, see setApprovals()
     */
    @Deprecated
    public void setApprovalSettings(Collection<Integer> approvalSettings) {
        data.put(APPROVALSETTINGS, approvalSettings);
    }

    /**
     * @return the number of different administrators that needs to approve an action, default 1.
     * @deprecated since 6.6.0, use the appropriate approval profile instead. 
     * Needed in order to be able to upgrade from 6.5 and earlier
     */
    @Deprecated
    public int getNumOfRequiredApprovals() {
        if (data.get(NUMBEROFREQAPPROVALS) == null) {
            return 1;
        }
        return ((Integer) data.get(NUMBEROFREQAPPROVALS)).intValue();
    }

    /**
     * The number of different administrators that needs to approve
     * @deprecated since 6.6.0, use the appropriate approval profile instead. 
     * Needed in order to be able to upgrade from 6.5 and earlier
     */
    @Deprecated
    public void setNumOfRequiredApprovals(int numOfReqApprovals) {
        data.put(NUMBEROFREQAPPROVALS, Integer.valueOf(numOfReqApprovals));
    }
    
    /**
     * @return the id of the approval profile. Defult -1 (= none)
     * 
     * @deprecated since 6.8.0, see getApprovals()
     */
    @Deprecated
    public int getApprovalProfile() {
        if (data.get(APPROVALPROFILE) == null) {
            return -1;
        }
        return ((Integer) data.get(APPROVALPROFILE)).intValue();
    }

    /**
     * The id of the approval profile.
     * 
     * @deprecated since 6.8.0, see setApprovals()
     */
    @Deprecated
    public void setApprovalProfile(final int approvalProfileID) {
        data.put(APPROVALPROFILE, Integer.valueOf(approvalProfileID));
    }

    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {
        setEncodedValidity(cainfo.getEncodedValidity());
        data.put(DESCRIPTION, cainfo.getDescription());
        data.put(CRLPERIOD, Long.valueOf(cainfo.getCRLPeriod()));
        data.put(DELTACRLPERIOD, Long.valueOf(cainfo.getDeltaCRLPeriod()));
        data.put(CRLISSUEINTERVAL, Long.valueOf(cainfo.getCRLIssueInterval()));
        data.put(CRLOVERLAPTIME, Long.valueOf(cainfo.getCRLOverlapTime()));
        data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
        data.put(VALIDATORS, cainfo.getValidators());
        data.put(APPROVALS, cainfo.getApprovals());
        if (cainfo.getCertificateProfileId() > 0) {
            data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));
        }
        setKeepExpiredCertsOnCRL(cainfo.getKeepExpiredCertsOnCRL()); 

        if (cainfo.getCAToken() != null) {
            setCAToken(cainfo.getCAToken());
        }
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName());
        setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        setUseCertReqHistory(cainfo.isUseCertReqHistory());
        setUseUserStorage(cainfo.isUseUserStorage());
        setUseCertificateStorage(cainfo.isUseCertificateStorage());
        Collection<Certificate> newcerts = cainfo.getCertificateChain();
        if ((newcerts != null) && (newcerts.size() > 0)) {
            setCertificateChain(newcerts);
            Certificate cacert = newcerts.iterator().next();
            setExpireTime(CertTools.getNotAfter(cacert));  
        }
        // Update or create extended CA services
        final Collection<ExtendedCAServiceInfo> infos = cainfo.getExtendedCAServiceInfos();
        if (infos != null) {
            final Collection<ExtendedCAServiceInfo> newInfos = new ArrayList<ExtendedCAServiceInfo>();
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
        
        if (cainfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
            updateUninitializedCA(cainfo);
        }
        
        this.cainfo = cainfo;
    }
    
    /**
     * Called when an uninitialized CA is updated, either from updateCA
     * or from other places in the code.
     * 
     * A few more values are also set in the overridden method in X509CA.
     */
    public void updateUninitializedCA(CAInfo cainfo) {
        setSignedBy(cainfo.getSignedBy());
    }

    /**
     * 
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider. 
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if 
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     * @param notBefore null or a custom date to use as notBefore date
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param encodedValidity requested validity as SimpleTime string or ISO8601 date string (see ValidityDate.java).
     * @param certProfile
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @param cceConfig containing a list of available custom certificate extensions
     * @return
     * @throws Exception
     */
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicKey publicKey, int keyusage, Date notBefore, String encodedValidity,
            CertificateProfile certProfile, String sequence, AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
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
        return generateCertificate(cryptoToken, subject, null, publicKey, keyusage, notBefore, notAfter, certProfile, null, sequence, null, cceConfig);
    }

    /**
     * 
     * @param cryptoToken 
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider. 
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if 
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the
     *            profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @param ctParams Parameters for the CT extension. May contain references to session beans. NOTE: This parameter may be replaced with a map (for multiple extensions) in the future.
     * @param cceConfig containing a list of available custom certificate extensions
     * @return the generated certificate
     * 
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws CertificateExtensionException  if any of the certificate extensions were invalid
     * @throws CertificateCreateException if an error occurred when trying to create a certificate. 
     * @throws OperatorCreationException  if CA's private key contained an unknown algorithm or provider
     * @throws IllegalNameException if the name specified in the certificate request was invalid
     * @throws IllegalValidityException  if validity was invalid
     * @throws InvalidAlgorithmException  if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid. 
     * @throws CAOfflineException if the CA wasn't active
     * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
     * @throws IllegalKeyException if the using public key is not allowed to be used by specified certProfile
     */
    public abstract Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request,
            PublicKey publicKey, int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig) throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException,
            IllegalValidityException, IllegalNameException, OperatorCreationException, CertificateCreateException, CertificateExtensionException,
            SignatureException, IllegalKeyException;

    /**
     * 
     * @param providedRequestMessage provided request message containing optional information, and will be set with the signing key and provider. 
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Can be null. Its public key is going to be used if 
     * providedPublicKey == null && subject.extendedInformation.certificateRequest == null
     * @param providedPublicKey provided public key which will have precedence over public key from providedRequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of providedRequestMessage and providedPublicKey
     */
    public final Certificate generateCertificate(CryptoToken cryptoToken, final EndEntityInformation subject, final RequestMessage request,
            final PublicKey publicKey, final int keyusage, final Date notBefore, final Date notAfter, final CertificateProfile certProfile,
            final Extensions extensions, final String sequence, final AvailableCustomCertificateExtensionsConfiguration cceConfig) 
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException,
            IllegalValidityException, IllegalNameException, OperatorCreationException, CertificateCreateException, CertificateExtensionException,
            SignatureException, IllegalKeyException {
        return generateCertificate(cryptoToken, subject, request, publicKey, keyusage, notBefore, notAfter, certProfile, extensions, sequence, null, cceConfig);
    }
    

    public abstract X509CRLHolder generateCRL(CryptoToken cryptoToken,Collection<RevokedCertInfo> certs, int crlnumber) throws Exception;

    public abstract X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) throws Exception;

    /**
     * Create a signed PKCS#7 / CMS message.
     * 
     * @param cryptoToken
     * @param cert
     * @param includeChain
     * @return
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
     * Creates a certificate signature request CSR), that can be sent to an external Root CA. Request format can vary depending on the type of CA. For
     * X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are created.
     * 
     * @param attributes PKCS10 attributes to be included in the request, a Collection of ASN1Encodable objects, ready to put in the request. Can be
     *            null.
     * @param signAlg the signature algorithm used by the CA
     * @param cacert the CAcertficate the request is targeted for, may be used or ignored by implementation depending on the request type created.
     * @param signatureKeyPurpose which CA token key pair should be used to create the request, normally SecConst.CAKEYPURPOSE_CERTSIGN but can also
     *            be SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
     * @return byte array with binary encoded request
     */
    public abstract byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose)
            throws CryptoTokenOfflineException;

    public abstract byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException;

    /**
     * General encryption method used to encrypt using a CA
     * 
     * @param data the data to encrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return encrypted data
     * @throws CryptoTokenOfflineException If crypto token is off-line so encryption key can not be used.
     * @throws CMSException In case parsing/encryption of CMS data fails. 
     * @throws NoSuchProviderException If encryption provider is not available.
     * @throws NoSuchAlgorithmException If desired encryption algorithm is not available.
     * @throws IOException In case reading/writing data streams failed during encryption
     */
    public abstract byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose) throws CryptoTokenOfflineException, NoSuchAlgorithmException, NoSuchProviderException, CMSException, IOException;

    /**
     * General encryption method used to decrypt using a CA
     * 
     * @param data the data to decrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return decrypted data
     * @throws CMSException In case parsing/decryption of CMS data fails. 
     * @throws CryptoTokenOfflineException If crypto token is off-line so decryption key can not be used.
     */
    public abstract byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose) throws CMSException, CryptoTokenOfflineException;

    // Methods used with extended services
    /**
     * Initializes the ExtendedCAService
     * 
     * @param cryptoToken the cryptotoken used to initiate the service
     * @param type the type of the extended key service
     * @param ca the CA used to initiate the service
     * @param cceConfig containing a list of available custom certificate extensions
     */
    public void initExtendedService(CryptoToken cryptoToken, int type, CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
        ExtendedCAService service = getExtendedCAService(type);
        if (service != null) {
            service.init(cryptoToken, ca, cceConfig);
            setExtendedCAService(service);
        }
    }

    /** Method used to retrieve information about the service. */
    public ExtendedCAServiceInfo getExtendedCAServiceInfo(int type) {
        ExtendedCAServiceInfo ret = null;
        ExtendedCAService service = getExtendedCAService(type);
        if (service != null) {
            ret = service.getExtendedCAServiceInfo();
        }
        return ret;
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
        service.setCA(this);
        return service.extendedService(cryptoToken, request);
    }

    @SuppressWarnings("rawtypes")
    public HashMap getExtendedCAServiceData(int type) {
        HashMap serviceData = (HashMap) data.get(EXTENDEDCASERVICE + type); 
        return serviceData;
    }

    public void setExtendedCAServiceData(int type, @SuppressWarnings("rawtypes") HashMap serviceData) {
        data.put(EXTENDEDCASERVICE + type, serviceData);
    }

    protected ExtendedCAService getExtendedCAService(int type) {
        ExtendedCAService returnval = null;
        try {
            returnval = (ExtendedCAService) extendedcaservicemap.get(Integer.valueOf(type));
            if (returnval == null) {
            	@SuppressWarnings("rawtypes")
                HashMap serviceData = getExtendedCAServiceData(type);
                if (serviceData != null) {
                    // We must have run upgrade on the extended CA services for this to work
                    String implClassname = (String) serviceData.get(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS);
                    if (implClassname == null) {
                    	log.error("implementation classname is null for extended service type: "+type+". Service not created.");
                    } else {
                    	if (log.isDebugEnabled()) {
                    		log.debug("implementation classname for extended service type: "+type+" is "+implClassname);
                    	}
                        Class<?> implClass = Class.forName(implClassname);
                        returnval = (ExtendedCAService) implClass.getConstructor(HashMap.class).newInstance(new Object[] { serviceData });
                        extendedcaservicemap.put(Integer.valueOf(type), returnval);                    	
                    }
                } else {
                	log.error("Servicedata is null for extended CA service of type: "+type);                	
                }
            }
        } catch (ClassNotFoundException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (IllegalArgumentException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (SecurityException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (InstantiationException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (IllegalAccessException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (InvocationTargetException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        } catch (NoSuchMethodException e) {
            log.warn("Extended CA service of type " + type + " can not get created: ", e);
        }
        return returnval;
    }

    @SuppressWarnings("rawtypes")
    public void setExtendedCAService(ExtendedCAService extendedcaservice) {
        ExtendedCAServiceInfo info = extendedcaservice.getExtendedCAServiceInfo();
        setExtendedCAServiceData(info.getType(), (HashMap)extendedcaservice.saveData());
        extendedcaservicemap.put(Integer.valueOf(info.getType()), extendedcaservice);
    }

    /** Returns a Collection of ExternalCAServices (int) added to this CA. */
    @SuppressWarnings("unchecked")
    public Collection<Integer> getExternalCAServiceTypes() {
        if (data.get(EXTENDEDCASERVICES) == null) {
            return new ArrayList<Integer>();
        }
        return (Collection<Integer>) data.get(EXTENDEDCASERVICES);
    }

    /**
     * Method to upgrade new (or existing externacaservices) This method needs to be called outside the regular upgrade since the CA isn't
     * instantiated in the regular upgrade.
     */
    public abstract boolean upgradeExtendedCAServices();

    /** Create a certificate with all the current CA certificate info, but signed by the old issuer */
    public abstract void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile, 
            AvailableCustomCertificateExtensionsConfiguration cceConfig) throws CryptoTokenOfflineException;

    /** Store the latest link certificate in this object. */
    protected void updateLatestLinkCertificate(byte[] encodedLinkCertificate) {
        if (encodedLinkCertificate == null) {
            data.remove(LATESTLINKCERTIFICATE);
        } else {
            try {
                data.put(LATESTLINKCERTIFICATE, new String(Base64.encode(encodedLinkCertificate),"UTF8"));
            } catch (final UnsupportedEncodingException e) {
                throw new RuntimeException(e);  // Lack of UTF8 would be fatal.
            }
        }
    }

    /** @return the CA latest link certificate or null */
    public byte[] getLatestLinkCertificate() {
        if (data.get(LATESTLINKCERTIFICATE) == null) {
            return null;
        }
        try {
            return Base64.decode(((String)data.get(LATESTLINKCERTIFICATE)).getBytes("UTF8"));
        } catch (final UnsupportedEncodingException e) {
            throw new RuntimeException(e);  // Lack of UTF8 would be fatal.
        }
    }
}
