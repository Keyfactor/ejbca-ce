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

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
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
 * Implementation of operations common for all CA types
 * @version $Id$
 *
 */
public abstract class CABaseCommon extends UpgradeableDataHashMap implements CACommon {
    
    private static final long serialVersionUID = 1L;

    private static Logger log = Logger.getLogger(CABaseCommon.class);
    
    private static final InternalResources intres = InternalResources.getInstance();
    
    public static final String CATYPE = "catype";
    @Deprecated
    protected static final String VALIDITY = "validity";
    protected static final String ENCODED_VALIDITY = "encodedvalidity";
    protected static final String EXPIRETIME = "expiretime";
    protected static final String SIGNEDBY = "signedby";
    protected static final String DESCRIPTION = "description";
    protected static final String REVOCATIONREASON = "revokationreason";
    protected static final String REVOCATIONDATE = "revokationdate";
    protected static final String CRLPERIOD = "crlperiod";
    protected static final String DELTACRLPERIOD = "deltacrlperiod";

    // protected fields.
    protected static final String SUBJECTDN = "subjectdn";
    protected static final String SUBJECTALTNAME = "subjectaltname";
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
    protected static final String REQUESTCERTCHAIN = "requestcertchain";
    protected static final String EXTENDEDCASERVICES = "extendedcaservices";
    protected static final String EXTENDEDCASERVICE = "extendedcaservice";
    protected static final String USENOCONFLICTCERTIFICATEDATA = "usenoconflictcertificatedata";
    protected static final String SERIALNUMBEROCTETSIZE = "serialnumberoctetsize";
    private static final String LATESTLINKCERTIFICATE = "latestLinkCertificate";
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

    
    private CAInfo cainfo = null;
    private CAToken caToken = null;
    private ArrayList<Certificate> requestcertchain = null;
    private ArrayList<Certificate> certificatechain = null;
    private ArrayList<Certificate> renewedcertificatechain = null;

    public void init(CAInfo cainfo) {
        data = new LinkedHashMap<>();
        this.cainfo = cainfo;
        setSignedBy(cainfo.getSignedBy());
        data.put(DESCRIPTION, cainfo.getDescription());
        data.put(REVOCATIONREASON, Integer.valueOf(-1));
        data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));

    }
    
    /** Constructor used when retrieving existing CA from database. */
    public void init(HashMap<Object, Object> data) {
        loadData(data);
    }
    
    public void setCAInfo(CAInfo cainfo) {
        this.cainfo = cainfo;
    }

    public CAInfo getCAInfo() {
        return this.cainfo;
    }
    
    public int getCertificateProfileId() {
        return ((Integer) data.get(CERTIFICATEPROFILEID)).intValue();
    }
    
    public String getSubjectDN() {
        return cainfo.getSubjectDN();
    }

    public void setSubjectDN(String subjectDn) {
        cainfo.subjectdn = subjectDn;
    }
    
    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.CACommon#getSubjectAltName()
     */
    @Override
    public String getSubjectAltName() {
        return (String) data.get(SUBJECTALTNAME);
    }

    /* (non-Javadoc)
     * @see org.cesecore.certificates.ca.CACommon#setSubjectAltName(java.lang.String)
     */
    @Override
    public void setSubjectAltName(final String altName) {
        data.put(SUBJECTALTNAME, altName);
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

    /**
     * @return one of CAInfo.CATYPE_CVC or CATYPE_X509
     */
    public int getCAType() {
        return ((Integer) data.get(CATYPE)).intValue();
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

    /** @return the CAs token reference. */
    public CAToken getCAToken() {
        if (caToken == null) {
            @SuppressWarnings("unchecked")
            LinkedHashMap<Object, Object> tokendata = (LinkedHashMap<Object, Object>) data.get(CATOKENDATA);
            final CAToken ret = new CAToken(tokendata);
            String signaturealg = (String)tokendata.get(CAToken.SIGNATUREALGORITHM);
            String encryptionalg = (String)tokendata.get(CAToken.ENCRYPTIONALGORITHM);
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
                this.requestcertchain = new ArrayList<>();
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
        final ArrayList<String> storechain = new ArrayList<>();
        for (final Certificate cert : requestcertificatechain) {
            try {
                storechain.add(new String(Base64.encode(cert.getEncoded())));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        data.put(REQUESTCERTCHAIN, storechain);
        this.requestcertchain = new ArrayList<>();
        this.requestcertchain.addAll(requestcertificatechain);
    }
    
    /**
     * Returns a collection of CA-certificates, with this CAs cert i position 0, or null if no CA-certificates exist. The root CA certificate will
     * thus be in the last position.
     *
     * @return Collection of Certificate
     */
    public List<Certificate> getCertificateChain() {
        if (certificatechain == null) {
            @SuppressWarnings("unchecked")
            Collection<String> storechain = (Collection<String>) data.get(CERTIFICATECHAIN);
            if (storechain == null) {
                return null;
            }
            this.certificatechain = new ArrayList<>();
            for (final String b64Cert : storechain) {
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
                    throw new IllegalStateException(e);
                }
            }
        }
        return certificatechain;
    }

    public void setCertificateChain(final List<Certificate> certificatechain) {
        final ArrayList<String> storechain = new ArrayList<>();
        for (final Certificate cert : certificatechain) {
            try {
                storechain.add(new String(Base64.encode(cert.getEncoded())));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException(e);
            }
        }
        data.put(CERTIFICATECHAIN, storechain);
        this.certificatechain = new ArrayList<>(certificatechain);
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
            renewedcertificatechain = new ArrayList<>();
            for (final String b64Cert : storechain) {
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
        ArrayList<String> storechain = new ArrayList<>();
        for (Certificate cert : certificatechain) {
            try {
                String b64Cert = new String(Base64.encode(cert.getEncoded()));
                storechain.add(b64Cert);
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Renewed certificates could not be encoded", e);
            }
        }
        data.put(RENEWEDCERTIFICATECHAIN, storechain);

        renewedcertificatechain = new ArrayList<>();
        renewedcertificatechain.addAll(certificatechain);
        cainfo.setRenewedCertificateChain(certificatechain);
    }
    
    public void setRolloverCertificateChain(Collection<Certificate> certificatechain) {
        Iterator<Certificate> iter = certificatechain.iterator();
        ArrayList<String> storechain = new ArrayList<>();
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
        final List<Certificate> chain = new ArrayList<>(storechain.size());
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
        Certificate ret = certificatechain.get(0);
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

    public void updateCA(CryptoToken cryptoToken, CAInfo cainfo, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws InvalidAlgorithmException {

        data.put(DESCRIPTION, cainfo.getDescription());
        if (cainfo.getCertificateProfileId() > 0) {
            data.put(CERTIFICATEPROFILEID, Integer.valueOf(cainfo.getCertificateProfileId()));
        }
        if (cainfo.getCAToken() != null) {
            setCAToken(cainfo.getCAToken());
        }
        List<Certificate> newcerts = cainfo.getCertificateChain();
        if ((newcerts != null) && (newcerts.size() > 0)) {
            setCertificateChain(newcerts);
            Certificate cacert = newcerts.iterator().next();
            setExpireTime(CertTools.getNotAfter(cacert));
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

    /** Create a certificate with all the current CA certificate info, but signed by the old issuer */
    public abstract void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException;
        
    
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
    
    /** Store the latest link certificate in this object. */
    protected void updateLatestLinkCertificate(byte[] encodedLinkCertificate) {
        if (encodedLinkCertificate == null) {
            data.remove(LATESTLINKCERTIFICATE);
        } else {
            try {
                data.put(LATESTLINKCERTIFICATE, new String(Base64.encode(encodedLinkCertificate), "UTF8"));
            } catch (final UnsupportedEncodingException e) {
                throw new RuntimeException(e); // Lack of UTF8 would be fatal.
            }
        }
    }
    
}
