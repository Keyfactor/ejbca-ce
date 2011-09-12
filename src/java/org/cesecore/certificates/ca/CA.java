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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;

import org.apache.commons.lang.ArrayUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.internal.CATokenCacheManager;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

/**
 * CA is a base class that should be inherited by all CA types
 * 
 * Based on EJBCA version: CA.java 11112 2011-01-09 16:17:33Z anatom
 * 
 * @version $Id: CA.java 1073 2011-09-04 19:36:38Z tomas $
 */
public abstract class CA extends UpgradeableDataHashMap implements Serializable {

    private static final long serialVersionUID = -8755429830955594642L;

    /** Log4j instance */
    private static Logger log = Logger.getLogger(CA.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    public static final String TRUE = "true";
    public static final String FALSE = "false";

    // protected fields.
    public static final String CATYPE = "catype";
    protected static final String SUBJECTDN = "subjectdn";
    protected static final String CAID = "caid";
    protected static final String NAME = "name";
    protected static final String STATUS = "status";
    protected static final String VALIDITY = "validity";
    protected static final String EXPIRETIME = "expiretime";
    protected static final String CERTIFICATECHAIN = "certificatechain";
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
    private static final String FINISHUSER = "finishuser";
    protected static final String REQUESTCERTCHAIN = "requestcertchain";
    protected static final String EXTENDEDCASERVICES = "extendedcaservices";
    protected static final String EXTENDEDCASERVICE = "extendedcaservice";
    protected static final String APPROVALSETTINGS = "approvalsettings";
    protected static final String NUMBEROFREQAPPROVALS = "numberofreqapprovals";
    protected static final String INCLUDEINHEALTHCHECK = "includeinhealthcheck";
    private static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = "doEnforceUniquePublicKeys";
    private static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = "doEnforceUniqueDistinguishedName";
    private static final String DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER = "doEnforceUniqueSubjectDNSerialnumber";
    private static final String USE_CERTREQ_HISTORY = "useCertreqHistory";
    private static final String USE_USER_STORAGE = "useUserStorage";
    private static final String USE_CERTIFICATE_STORAGE = "useCertificateStorage";

    private HashMap<Integer, ExtendedCAService> extendedcaservicemap = new HashMap<Integer, ExtendedCAService>();

    private ArrayList<Certificate> certificatechain = null;
    private ArrayList<Certificate> requestcertchain = null;

    private CAInfo cainfo = null;

    /** Creates a new instance of CA, this constructor should be used when a new CA is created */
    public CA(CAInfo cainfo) {
        data = new LinkedHashMap<Object, Object>();

        this.cainfo = cainfo;

        data.put(VALIDITY, new Long(cainfo.getValidity()));
        data.put(SIGNEDBY, Integer.valueOf(cainfo.getSignedBy()));
        data.put(DESCRIPTION, cainfo.getDescription());
        data.put(REVOCATIONREASON, Integer.valueOf(-1));
        data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));
        setCRLPeriod(cainfo.getCRLPeriod());
        setCRLIssueInterval(cainfo.getCRLIssueInterval());
        setCRLOverlapTime(cainfo.getCRLOverlapTime());
        setDeltaCRLPeriod(cainfo.getDeltaCRLPeriod());
        setCRLPublishers(cainfo.getCRLPublishers());
        setFinishUser(cainfo.getFinishUser());
        setIncludeInHealthCheck(cainfo.getIncludeInHealthCheck());
        setDoEnforceUniquePublicKeys(cainfo.isDoEnforceUniquePublicKeys());
        setDoEnforceUniqueDistinguishedName(cainfo.isDoEnforceUniqueDistinguishedName());
        setDoEnforceUniqueSubjectDNSerialnumber(cainfo.isDoEnforceUniqueSubjectDNSerialnumber());
        setUseCertReqHistory(cainfo.isUseCertReqHistory());
        setUseUserStorage(cainfo.isUseUserStorage());
        setUseCertificateStorage(cainfo.isUseCertificateStorage());

        Iterator<ExtendedCAServiceInfo> iter = cainfo.getExtendedCAServiceInfos().iterator();
        ArrayList<Integer> extendedservicetypes = new ArrayList<Integer>();
        while (iter.hasNext()) {
            ExtendedCAServiceInfo next = iter.next();
            createExtendedCAService(next);
            extendedservicetypes.add(next.getType());
        }
        data.put(EXTENDEDCASERVICES, extendedservicetypes);
        setApprovalSettings(cainfo.getApprovalSettings());
        setNumOfRequiredApprovals(cainfo.getNumOfReqApprovals());
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

    /** Constructor used when retrieving existing CA from database. */
    public CA(HashMap<Object, Object> data) {
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

    public long getValidity() {
        return ((Number) data.get(VALIDITY)).longValue();
    }

    public void setValidity(long validity) {
        data.put(VALIDITY, new Long(validity));
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
        data.put(CRLPERIOD, new Long(crlperiod));
    }

    public long getDeltaCRLPeriod() {
        if (data.containsKey(DELTACRLPERIOD)) {
            return ((Long) data.get(DELTACRLPERIOD)).longValue();
        } else {
            return 0;
        }
    }

    public void setDeltaCRLPeriod(long deltacrlperiod) {
        data.put(DELTACRLPERIOD, new Long(deltacrlperiod));
    }

    public long getCRLIssueInterval() {
        return ((Long) data.get(CRLISSUEINTERVAL)).longValue();
    }

    public void setCRLIssueInterval(long crlIssueInterval) {
        data.put(CRLISSUEINTERVAL, new Long(crlIssueInterval));
    }

    public long getCRLOverlapTime() {
        return ((Long) data.get(CRLOVERLAPTIME)).longValue();
    }

    public void setCRLOverlapTime(long crlOverlapTime) {
        data.put(CRLOVERLAPTIME, new Long(crlOverlapTime));
    }

    public Collection<Integer> getCRLPublishers() {
        return ((Collection<Integer>) data.get(CRLPUBLISHERS));
    }

    public void setCRLPublishers(Collection<Integer> crlpublishers) {
        data.put(CRLPUBLISHERS, crlpublishers);
    }

    public int getCertificateProfileId() {
        return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();
    }

    /**
     * Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalCryptoTokenException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is
     *             undefined.
     * @throws
     */
    protected CAToken getCAToken(int caid) throws IllegalCryptoTokenException {
        CAToken ret = CATokenCacheManager.instance().getCAToken(caid);
        if (ret == null) {
            // Not cached we have to create the crypto token
            HashMap tokendata = (HashMap) data.get(CATOKENDATA);
            ret = new CAToken(tokendata, caid);
            String signaturealg = (String) tokendata.get(CAToken.SIGNATUREALGORITHM);
            String encryptionalg = (String) tokendata.get(CAToken.ENCRYPTIONALGORITHM);
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

            CATokenCacheManager.instance().addCAToken(caid, ret);
        }
        return ret;
    }

    /**
     * Returns the CAs token. The token is fetched from the token registry, or created and added to the token registry.
     * 
     * @return The CAs token, be it soft or hard.
     * @throws IllegalCryptoTokenException If the token keystore is invalid (crypto error thrown by crypto provider), or the CA token type is
     *             undefined.
     */
    public CAToken getCAToken() throws IllegalCryptoTokenException {
        return getCAToken(getCAId());
    }

    /**
     * Sets the CA token. Adds or updates the token in the token registry.
     * 
     * @param catoken The CAs token, be it soft or hard.
     * @throws InvalidAlgorithmException 
     */
    public void setCAToken(CAToken catoken) throws InvalidAlgorithmException {
        // Check that the signature algorithm is one of the allowed ones
    	final String sigAlg = catoken.getTokenInfo().getSignatureAlgorithm();
        if (!ArrayUtils.contains(AlgorithmConstants.AVAILABLE_SIGALGS, sigAlg)) {
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", sigAlg);
            throw new InvalidAlgorithmException(msg);        	
        }
    	final String encAlg = catoken.getTokenInfo().getEncryptionAlgorithm();
        if (!ArrayUtils.contains(AlgorithmConstants.AVAILABLE_SIGALGS, encAlg)) {
            final String msg = intres.getLocalizedMessage("createcert.invalidsignaturealg", encAlg);
            throw new InvalidAlgorithmException(msg);        	
        }
        data.put(CATOKENDATA, catoken.saveData());
        CATokenCacheManager.instance().addCAToken(getCAId(), catoken);
    }

    /**
     * Returns a collection of CA certificates, or null if no request certificate chain exists
     */
    public Collection<Certificate> getRequestCertificateChain() {
        if (requestcertchain == null) {
            Collection<String> storechain = (Collection<String>) data.get(REQUESTCERTCHAIN);
            if (storechain != null) {
                Iterator<String> iter = storechain.iterator();
                this.requestcertchain = new ArrayList<Certificate>();
                while (iter.hasNext()) {
                    String b64Cert = (String) iter.next();
                    try {
                        this.requestcertchain.add(CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes())));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            }
        }
        return requestcertchain;
    }

    public void setRequestCertificateChain(Collection<Certificate> requestcertificatechain) {
        Iterator<Certificate> iter = requestcertificatechain.iterator();
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
            Collection<String> storechain = (Collection<String>) data.get(CERTIFICATECHAIN);
            if (storechain == null) {
                return null;
            }
            Iterator<String> iter = storechain.iterator();
            this.certificatechain = new ArrayList<Certificate>();
            while (iter.hasNext()) {
                String b64Cert = iter.next();
                try {
                    Certificate cert = CertTools.getCertfromByteArray(Base64.decode(b64Cert.getBytes()));
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

    public void setCertificateChain(Collection<Certificate> certificatechain) {
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
        data.put(CERTIFICATECHAIN, storechain);

        this.certificatechain = new ArrayList<Certificate>();
        this.certificatechain.addAll(certificatechain);
        this.cainfo.setCertificateChain(certificatechain);
    }

    /* Returns the CAs certificate, or null if no CA-certificates exist.
     */
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

    private boolean getBoolean(String key, boolean defaultValue) {
        final Object temp = data.get(key);
        if (temp != null && temp instanceof Boolean) {
            return ((Boolean) temp).booleanValue();
        }
        return defaultValue;
    }

    protected boolean getFinishUser() {
        return getBoolean(FINISHUSER, true);
    }

    private void setFinishUser(boolean finishuser) {
        data.put(FINISHUSER, new Boolean(finishuser));
    }

    protected boolean getIncludeInHealthCheck() {
        return getBoolean(INCLUDEINHEALTHCHECK, true);
    }

    protected void setIncludeInHealthCheck(boolean includeInHealthCheck) {
        data.put(INCLUDEINHEALTHCHECK, new Boolean(includeInHealthCheck));
    }

    public boolean isDoEnforceUniquePublicKeys() {
        return getBoolean(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, false);
    }

    private void setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
        data.put(DO_ENFORCE_UNIQUE_PUBLIC_KEYS, new Boolean(doEnforceUniquePublicKeys));
    }

    public boolean isDoEnforceUniqueDistinguishedName() {
        return getBoolean(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, false);
    }

    private void setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
        data.put(DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME, new Boolean(doEnforceUniqueDistinguishedName));
    }

    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return getBoolean(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, false);
    }

    private void setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
        data.put(DO_ENFORCE_UNIQUE_SUBJECTDN_SERIALNUMBER, new Boolean(doEnforceUniqueSubjectDNSerialnumber));
    }

    /** whether certificate request history should be used or not, default true as was the case before 3.10.4 */
    public boolean isUseCertReqHistory() {
        return getBoolean(USE_CERTREQ_HISTORY, true);
    }

    private void setUseCertReqHistory(boolean useCertReqHistory) {
        data.put(USE_CERTREQ_HISTORY, Boolean.valueOf(useCertReqHistory));
    }

    /** whether users should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseUserStorage() {
        return getBoolean(USE_USER_STORAGE, true);
    }

    private void setUseUserStorage(boolean useUserStorage) {
        data.put(USE_USER_STORAGE, Boolean.valueOf(useUserStorage));
    }

    /** whether issued certificates should be stored or not, default true as was the case before 3.10.x */
    public boolean isUseCertificateStorage() {
        return getBoolean(USE_CERTIFICATE_STORAGE, true);
    }

    private void setUseCertificateStorage(boolean useCertificateStorage) {
        data.put(USE_CERTIFICATE_STORAGE, Boolean.valueOf(useCertificateStorage));
    }

    /**
     * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals, default none
     * 
     * 
     * @return Collection of Integer, never null
     */
    public Collection<Integer> getApprovalSettings() {
        if (data.get(APPROVALSETTINGS) == null) {
            return new ArrayList<Integer>();
        }
        return (Collection<Integer>) data.get(APPROVALSETTINGS);
    }

    /**
     * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which action that requires approvals
     */
    public void setApprovalSettings(Collection<Integer> approvalSettings) {
        data.put(APPROVALSETTINGS, approvalSettings);
    }

    /**
     * Returns the number of different administrators that needs to approve an action, default 1.
     */
    public int getNumOfRequiredApprovals() {
        if (data.get(NUMBEROFREQAPPROVALS) == null) {
            return 1;
        }
        return ((Integer) data.get(NUMBEROFREQAPPROVALS)).intValue();
    }

    /**
     * The number of different administrators that needs to approve
     */
    public void setNumOfRequiredApprovals(int numOfReqApprovals) {
        data.put(NUMBEROFREQAPPROVALS, Integer.valueOf(numOfReqApprovals));
    }

    public void updateCA(CAInfo cainfo) throws IllegalCryptoTokenException {
        data.put(VALIDITY, new Long(cainfo.getValidity()));
        data.put(DESCRIPTION, cainfo.getDescription());
        data.put(CRLPERIOD, new Long(cainfo.getCRLPeriod()));
        data.put(DELTACRLPERIOD, new Long(cainfo.getDeltaCRLPeriod()));
        data.put(CRLISSUEINTERVAL, new Long(cainfo.getCRLIssueInterval()));
        data.put(CRLOVERLAPTIME, new Long(cainfo.getCRLOverlapTime()));
        data.put(CRLPUBLISHERS, cainfo.getCRLPublishers());
        data.put(APPROVALSETTINGS, cainfo.getApprovalSettings());
        data.put(NUMBEROFREQAPPROVALS, Integer.valueOf(cainfo.getNumOfReqApprovals()));
        if (cainfo.getCertificateProfileId() > 0) {
            data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));
        }
        CAToken token = getCAToken();
        if (token != null) {
            token.updateTokenInfo(cainfo.getCATokenInfo());
            try {
				setCAToken(token);
			} catch (InvalidAlgorithmException e) {
				throw new IllegalCryptoTokenException(e);
			}
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
        }

        // Update or create extended CA services
        Iterator<ExtendedCAServiceInfo> iter = cainfo.getExtendedCAServiceInfos().iterator();
        Collection<Integer> extendedservicetypes = getExternalCAServiceTypes(); // Se we can add things to this
        while (iter.hasNext()) {
            ExtendedCAServiceInfo info = iter.next();
            ExtendedCAService service = this.getExtendedCAService(info.getType());
            if (service == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Creating new extended CA service of type: "+info.getType());
            	}
                createExtendedCAService(info);
                extendedservicetypes.add(info.getType());
            } else {
            	if (log.isDebugEnabled()) {
            		log.debug("Updating extended CA service of type: "+info.getType());
            	}
                service.update(info, this);
                setExtendedCAService(service);
            }
        }
        data.put(EXTENDEDCASERVICES, extendedservicetypes);
        this.cainfo = cainfo;
    }

    /**
     * 
     * @param subject
     * @param publicKey
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param validity requested validity in days if less than Integer.MAX_VALUE, otherwise it's milliseconds since epoc.
     * @param certProfile
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @return
     * @throws Exception
     */
    public Certificate generateCertificate(EndEntityInformation subject, PublicKey publicKey, int keyusage, long validity,
            CertificateProfile certProfile, String sequence) throws Exception {
        // Calculate the notAfter date
        final Date notBefore = new Date();
        final Date notAfter;
        if (validity != -1) {
            notAfter = ValidityDate.getDate(validity, notBefore);
        } else {
            notAfter = null;
        }
        return generateCertificate(subject, null, publicKey, keyusage, notBefore, notAfter, certProfile, null, sequence);
    }

    /**
     * 
     * @param subject
     * @param requestX509Name if the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN
     * @param publicKey
     * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
     * @param notBefore
     * @param notAfter
     * @param certProfile
     * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the
     *            profile default extensions should be used.
     * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
     *            CVC CAs for sequence field. Can be set to null.
     * @return
     * @throws Exception
     */
    public abstract Certificate generateCertificate(EndEntityInformation subject, X509Name requestX509Name, PublicKey publicKey, int keyusage,
            Date notBefore, Date notAfter, CertificateProfile certProfile, X509Extensions extensions, String sequence) throws Exception;

    public abstract CRL generateCRL(Collection<RevokedCertInfo> certs, int crlnumber) throws Exception;

    public abstract CRL generateDeltaCRL(Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber) throws Exception;

    public abstract byte[] createPKCS7(Certificate cert, boolean includeChain) throws SignRequestSignatureException;

    /**
     * Creates a certificate signature request CSR), that can be sent to an external Root CA. Request format can vary depending on the type of CA. For
     * X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are created.
     * 
     * @param attributes PKCS10 attributes to be included in the request, a Collection of DEREncodable objects, ready to put in the request. Can be
     *            null.
     * @param signAlg the signature algorithm used by the CA
     * @param cacert the CAcertficate the request is targeted for, may be used or ignored by implementation depending on the request type created.
     * @param signatureKeyPurpose which CA token key pair should be used to create the request, normally SecConst.CAKEYPURPOSE_CERTSIGN but can also
     *            be SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
     * @return byte array with binary encoded request
     */
    public abstract byte[] createRequest(Collection<DEREncodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose)
            throws CryptoTokenOfflineException;

    /**
     * Signs a certificate signature request CSR), that can be sent to an external CA. This signature can be use to authenticate the original request.
     * mainly used for CVC CAs where the CVC requests is created and (self)signed by the DV and then the CVCA adds an outer signature to the request.
     * The signature algorithm used to sign the request will be whatever algorithm the CA uses to sign certificates.
     * 
     * @param request the binary coded request to be signed
     * @param usepreviouskey true if the CAs previous key should be used to sign the request, if the CA has generated new keys. Primarily used to
     *            create authenticated CVC requests.
     * @param createlinkcert true if the signed request should be a link certificate. Primarily used to create CVC link certificates.
     * @return byte array with binary encoded signed request or the original request of the CA can not create an additional signature on the passed in
     *         request.
     */
    public abstract byte[] signRequest(byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CryptoTokenOfflineException;

    public byte[] encryptKeys(KeyPair keypair) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(baos);
        os.writeObject(keypair);
        return encryptData(baos.toByteArray(), CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
    }

    public KeyPair decryptKeys(byte[] data) throws Exception {
        byte[] recdata = decryptData(data, CATokenConstants.CAKEYPURPOSE_KEYENCRYPT);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
        return (KeyPair) ois.readObject();
    }

    /**
     * General encryption method used to encrypt using a CA
     * 
     * @param data the data to encrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return encrypted data
     */
    public abstract byte[] encryptData(byte[] data, int keyPurpose) throws Exception;

    /**
     * General encryption method used to decrypt using a CA
     * 
     * @param data the data to decrypt
     * @param keyPurpose should be one of the SecConst.CAKEYPURPOSE_ constants
     * @return decrypted data
     */
    public abstract byte[] decryptData(byte[] data, int cAKeyPurpose) throws Exception;

    // Methods used with extended services
    /**
     * Initializes the ExtendedCAService
     * 
     * @param info contains information used to activate the service.
     */
    public void initExtendedService(int type, CA ca) throws Exception {
        ExtendedCAService service = getExtendedCAService(type);
        if (service != null) {
            service.init(ca);
            setExtendedCAService(service);
        }
    }

    /**
     * Method used to retrieve information about the service.
     */

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
     */
    public ExtendedCAServiceResponse extendedService(ExtendedCAServiceRequest request) throws ExtendedCAServiceRequestException,
            IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
        ExtendedCAService service = getExtendedCAService(request.getServiceType());
        if (service == null) {
        	final String msg = "Extended CA service is null for service request: "+request.getClass().getName();
        	log.error(msg);
        	throw new IllegalExtendedCAServiceRequestException();
        }
        // Enrich request with CA in order for the service to be able to use CA keys and certificates
        service.setCA(this);
        return service.extendedService(request);
    }

    public HashMap getExtendedCAServiceData(int type) {
        HashMap serviceData = (HashMap) data.get(EXTENDEDCASERVICE + type); 
        return serviceData;
    }

    public void setExtendedCAServiceData(int type, HashMap serviceData) {
        data.put(EXTENDEDCASERVICE + type, serviceData);
    }

    protected ExtendedCAService getExtendedCAService(int type) {
        ExtendedCAService returnval = null;
        try {
            returnval = (ExtendedCAService) extendedcaservicemap.get(Integer.valueOf(type));
            if (returnval == null) {
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

    public void setExtendedCAService(ExtendedCAService extendedcaservice) {
        ExtendedCAServiceInfo info = extendedcaservice.getExtendedCAServiceInfo();
        setExtendedCAServiceData(info.getType(), (HashMap)extendedcaservice.saveData());
        extendedcaservicemap.put(Integer.valueOf(info.getType()), extendedcaservice);
    }

    /**
     * Returns a Collection of ExternalCAServices (int) added to this CA.
     * 
     */
    public Collection<Integer> getExternalCAServiceTypes() {
        if (data.get(EXTENDEDCASERVICES) == null) {
            return new ArrayList<Integer>();
        }
        return (Collection<Integer>) data.get(EXTENDEDCASERVICES);
    }

    /**
     * Method to upgrade new (or existing externacaservices) This method needs to be called outside the regular upgrade since the CA isn't
     * instantiated in the regular upgrade.
     * 
     */
    public abstract boolean upgradeExtendedCAServices();
}
