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

package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.JDBCUtil.Preparer;

/**
 * Publisher writing certificates to an external Database, used by external OCSP responder.
 *
 * @version $Id$
 *
 */
public class ValidationAuthorityPublisher extends BasePublisher implements ICustomPublisher {

    private static final long serialVersionUID = -8046305645562531532L;

    private static final Logger log = Logger.getLogger(ValidationAuthorityPublisher.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    public static final float LATEST_VERSION = 1;

    public static final int TYPE_VAPUBLISHER = 5;

    protected static final String DATASOURCE = "dataSource";
    protected static final String PROTECT = "protect";
    protected static final String STORECERT = "storeCert";
    protected static final String STORECRL = "storeCRL";
    protected static final String ONLYPUBLISHREVOKED = "onlyPublishRevoked";

    // Default values
    public static final String DEFAULT_DATASOURCE = "java:/OcspDS";
    public static final boolean DEFAULT_PROTECT = false;

    private final static String insertCertificateSQL = "INSERT INTO CertificateData (base64Cert,subjectDN,issuerDN,cAFingerprint,serialNumber,status,type,username,expireDate,revocationDate,revocationReason,tag,certificateProfileId,updateTime,subjectKeyId,fingerprint,rowVersion) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)";
    private final static String updateCertificateSQL = "UPDATE CertificateData SET base64Cert=?,subjectDN=?,issuerDN=?,cAFingerprint=?,serialNumber=?,status=?,type=?,username=?,expireDate=?,revocationDate=?,revocationReason=?,tag=?,certificateProfileId=?,updateTime=?,subjectKeyId=?,rowVersion=(rowVersion+1) WHERE fingerprint=?";
    private final static String deleteCertificateSQL = "DELETE FROM CertificateData WHERE fingerprint=?";

    /**
     *
     */
    public ValidationAuthorityPublisher() {
        super();
        this.data.put(TYPE, Integer.valueOf(TYPE_VAPUBLISHER));
        setDataSource(DEFAULT_DATASOURCE);
        setProtect(DEFAULT_PROTECT);
    }

    /**
     *  Sets the data source property for the publisher.
     */
    public void setDataSource(String dataSource) {
        this.data.put(DATASOURCE, dataSource);
    }

    /**
     *  Sets the property protect for the publisher.
     */
    public void setProtect(boolean protect) {
        this.data.put(PROTECT, Boolean.valueOf(protect));
    }

    /**
     * @return The value of the property data source
     */
    public String getDataSource() {
        return (String) this.data.get(DATASOURCE);
    }

    /**
     * @return The value of the property protect
     */
    public boolean getProtect() {
        return ((Boolean) this.data.get(PROTECT)).booleanValue();
    }

    /**
     *  Set to false if the certificate should not be published.
     */
    public void setStoreCert(boolean storecert) {
        this.data.put(STORECERT, Boolean.valueOf(storecert));
    }

    /**
     * @return Should the certificate be published
     */
    public boolean getStoreCert() {
        final Object o = this.data.get(STORECERT);
        if (o == null) {
            return true; // default value is true
        }
        return ((Boolean) o).booleanValue();
    }

    /**
     *  Set to true if only revoked certificates should be published.
     */
    public void setOnlyPublishRevoked(boolean storecert) {
        this.data.put(ONLYPUBLISHREVOKED, Boolean.valueOf(storecert));
    }

    /**
     * @return Should only revoked certificates be published?
     */
    public boolean getOnlyPublishRevoked() {
        final Object o = this.data.get(ONLYPUBLISHREVOKED);
        if (o == null) {
            return false; // default value is false
        }
        return ((Boolean) o).booleanValue();
    }

    /**
     *  Set to true if the CRL should be published.
     */
    public void setStoreCRL(boolean storecert) {
        this.data.put(STORECRL, Boolean.valueOf(storecert));
    }

    /**
     * @return Should the CRL be published.
     */
    public boolean getStoreCRL() {
        final Object o = this.data.get(STORECRL);
        if (o == null) {
            return false; // default value is false
        }
        return ((Boolean) o).booleanValue();
    }

    @Override
    public void init(Properties properties) {
        setDataSource(properties.getProperty(DATASOURCE));
        log.debug("dataSource='" + getDataSource() + "'.");
        String prot = properties.getProperty(PROTECT, "false"); // false is default for this
        setProtect(StringUtils.equalsIgnoreCase(prot, "true"));
        log.debug("protect='" + getProtect() + "'.");
        String storecert = properties.getProperty(STORECERT, "true"); // true is default for this
        setStoreCert(StringUtils.equalsIgnoreCase(storecert, "true"));
        log.debug("storeCert='" + getStoreCert() + "'.");
    }

    private class StoreCertPreparer implements Preparer {
        private final Certificate incert;
        private final String username;
        private final String cafp;
        private final int status;
        private final int type;
        private final long revocationDate;
        private final int reason;
        private final String tag;
        private final int certificateProfileId;
        private final long updateTime;
        boolean isDelete = false;

        StoreCertPreparer(Certificate ic, String un, String cfp, int s, long d, int r, int t, String tag, int profid, long utime) {
            super();
            this.incert = ic;
            this.username = un;
            this.cafp = cfp;
            this.status = s;
            this.revocationDate = d;
            this.reason = r;
            this.type = t;
            this.tag = tag;
            this.certificateProfileId = profid;
            this.updateTime = utime;
        }

        @Override
        public void prepare(PreparedStatement ps) throws Exception {
            if (this.isDelete) {
                prepareDelete(ps);
            } else {
                prepareNewUpdate(ps);
            }
        }

        private void prepareDelete(PreparedStatement ps) throws Exception {
            ps.setString(1, CertTools.getFingerprintAsString(this.incert));
        }

        private void prepareNewUpdate(PreparedStatement ps) throws Exception {
            // We can select to publish the whole certificate, or not to.
            // There are good reasons not to publish the whole certificate. It is large, thus making it a bit of heavy insert and it may
            // contain sensitive information.
            // On the other hand some OCSP Extension plug-ins may not work without the certificate.
            // A regular OCSP responder works fine without the certificate.
            final String cert;
            if (getStoreCert()) {
                cert = new String(Base64.encode(this.incert.getEncoded(), true));
            } else {
                cert = null;
            }
            ps.setString(1, cert);
            ps.setString(2, CertTools.getSubjectDN(this.incert));
            ps.setString(3, CertTools.getIssuerDN(this.incert));
            ps.setString(4, this.cafp);
            ps.setString(5, ((X509Certificate) this.incert).getSerialNumber().toString());
            ps.setInt(6, this.status);
            ps.setInt(7, this.type);
            ps.setString(8, this.username);
            ps.setLong(9, ((X509Certificate) this.incert).getNotAfter().getTime());
            ps.setLong(10, this.revocationDate);
            ps.setInt(11, this.reason);
            ps.setString(12, this.tag);
            ps.setInt(13, this.certificateProfileId);
            ps.setLong(14, this.updateTime);
            final String fingerprint = CertTools.getFingerprintAsString(this.incert);
            String subjectKeyId = null;
            try {
                subjectKeyId = new String(Base64.encode(KeyTools.createSubjectKeyId(this.incert.getPublicKey()).getKeyIdentifier(), false));
            } catch (Exception e) {
                log.warn("Error constructing subjectKeyId for certificate, using null: " + fingerprint);
            }
            ps.setString(15, subjectKeyId);
            ps.setString(16, fingerprint); // This is the last ? in the statement
        }

        @Override
        public String getInfoString() {
            return "Store:, Username: " + this.username + ", Issuer:" + CertTools.getIssuerDN(this.incert) + ", Serno: "
                    + CertTools.getSerialNumberAsString(this.incert) + ", Subject: " + CertTools.getSubjectDN(this.incert);
        }
    }

    private void updateCert(StoreCertPreparer prep) throws Exception {
        // If this is a revocation we assume that the certificate already exists in the database. In that case we will try an update first and if that fails an insert.
        if (JDBCUtil.execute(updateCertificateSQL, prep, getDataSource()) == 1) {
            return;
        }
        // If this is a revocation we tried an update below, if that failed we have to do an insert here
        JDBCUtil.execute(insertCertificateSQL, prep, getDataSource());
        // No exception throws, so this worked
    }

    private void deleteCert(StoreCertPreparer prep) throws Exception {
        prep.isDelete = true;
        JDBCUtil.execute(deleteCertificateSQL, prep, getDataSource());
    }

    private void newCert(StoreCertPreparer prep) throws Exception {
        try {
            JDBCUtil.execute(insertCertificateSQL, prep, getDataSource());
            // No exception throws, so this worked
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                log.debug(intres.getLocalizedMessage("publisher.entryexists", e.getMessage()));
            }
            if (JDBCUtil.execute(updateCertificateSQL, prep, getDataSource()) == 1) {
                return; // We updated exactly one row, which is what we expect
            }
            throw e; // better throw insert exception if this fallback fails.
        }
    }

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        if (getOnlyPublishRevoked()) {
            // If we should only publish revoked certificates and
            // - status is not revoked
            // - revocation reason is not REVOCATION_REASON_REMOVEFROMCRL even if status is active
            // Then we will not publish the certificate, in all other cases we will
            if ((status != CertificateConstants.CERT_REVOKED) && (revocationReason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) {
                if (log.isDebugEnabled()) {
                    log.debug("Will not publish certificate. Status: " + status + ", revocationReason: " + revocationReason);
                }
                return false;
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Will publish certificate. Status: " + status + ", revocationReason: " + revocationReason);
        }
        return true;
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isDebugEnabled()) {
            final String fingerprint = CertTools.getFingerprintAsString(incert);
            log.debug("Publishing certificate with fingerprint " + fingerprint + ", status " + status + ", type " + type + " to external VA.");
        }
        final StoreCertPreparer prep = new StoreCertPreparer(incert, username, cafp, status, revocationDate, revocationReason, type, tag,
                certificateProfileId, lastUpdate);
        final boolean doOnlyPublishRevoked = getOnlyPublishRevoked();
        try {
            if (doOnlyPublishRevoked) {
                if (status == CertificateConstants.CERT_REVOKED) {
                    newCert(prep); // 
                    return true;
                }
                if (revocationReason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) {
                    deleteCert(prep); // cert unrevoked, delete it from VA DB.
                    return true;
                }
                if (log.isDebugEnabled()) {
                    log.debug("Not publishing certificate with status " + status + ", type " + type
                            + " to external VA, we only publish revoked certificates.");
                }
                return true; // do nothing if new cert.
            }
            if (status == CertificateConstants.CERT_REVOKED) {
                updateCert(prep);
                return true;
            }
            newCert(prep);
            return true;
        } catch (Throwable e) {
            throwPublisherException(e, prep);
            return false;
        }
    }

    private class StoreCRLPreparer implements Preparer {
        private final String base64Crl;
        private final String cAFingerprint;
        private final int cRLNumber;
        private final int deltaCRLIndicator;
        private final String issuerDN;
        private final String fingerprint;
        private final long thisUpdate;
        private final long nextUpdate;

        StoreCRLPreparer(byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
            super();
            final X509CRL crl;
            try {
                crl = CertTools.getCRLfromByteArray(incrl);
                // Is it a delta CRL?
                this.deltaCRLIndicator = crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null ? 1 : -1;
                this.issuerDN = userDN;
                this.cRLNumber = number;
                this.cAFingerprint = cafp;
                this.base64Crl = new String(Base64.encode(incrl));
                this.fingerprint = CertTools.getFingerprintAsString(incrl);
                this.thisUpdate = crl.getThisUpdate().getTime();
                this.nextUpdate = crl.getNextUpdate().getTime();
                if (log.isDebugEnabled()) {
                    log.debug("Publishing CRL with fingerprint " + this.fingerprint + ", number " + number + " to external CRL store for the CA "
                            + this.issuerDN + (this.deltaCRLIndicator > 0 ? ". It is a delta CRL." : "."));
                }
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "CRL");
                log.error(msg, e);
                throw new PublisherException(msg);
            }
        }

        @Override
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setString(1, this.base64Crl);
            ps.setString(2, this.cAFingerprint);
            ps.setInt(3, this.cRLNumber);
            ps.setInt(4, this.deltaCRLIndicator);
            ps.setString(5, this.issuerDN);
            ps.setLong(6, this.thisUpdate);
            ps.setLong(7, this.nextUpdate);
            ps.setString(8, this.fingerprint);
        }

        @Override
        public String getInfoString() {
            return "Store CRL:, Issuer:" + this.issuerDN + ", Number: " + this.cRLNumber + ", Is delta: " + (this.deltaCRLIndicator > 0);
        }
    }

    private final static String insertCRLSQL = "INSERT INTO CRLData (base64Crl,cAFingerprint,cRLNumber,deltaCRLIndicator,issuerDN,thisUpdate,nextUpdate,fingerprint,rowVersion) VALUES (?,?,?,?,?,?,?,?,0)";
    private final static String updateCRLSQL = "UPDATE CRLData SET base64Crl=?,cAFingerprint=?,cRLNumber=?,deltaCRLIndicator=?,issuerDN=?,thisUpdate=?,nextUpdate=?,rowVersion=(rowVersion+1) WHERE fingerprint=?";

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (!getStoreCRL()) {
            if (log.isDebugEnabled()) {
                log.debug("No CRL published. The VA publisher is not configured to do it.");
            }
            return true;
        }
        final Preparer prep = new StoreCRLPreparer(incrl, cafp, number, userDN);
        try {
            JDBCUtil.execute(insertCRLSQL, prep, getDataSource());
        } catch (SQLException e) {
            if (log.isDebugEnabled()) {
                final String msg = intres.getLocalizedMessage("publisher.entryexists", e.getMessage());
                log.debug(msg, e);
            }
            try {
                JDBCUtil.execute(updateCRLSQL, prep, getDataSource());
            } catch (Exception ue) {
                throwPublisherException(ue, prep);
            }
        } catch (Throwable e) {
            // If it is an SQL exception, we probably had a duplicate key, so we are actually trying to re-publish
            throwPublisherException(e, prep);
        }
        return true;
    }

    void throwPublisherException(Throwable e, Preparer prep) throws PublisherException {
        final String lmsg = intres.getLocalizedMessage("publisher.errorvapubl", getDataSource(), prep.getInfoString());
        log.error(lmsg, e);
        final PublisherException pe = new PublisherException(lmsg);
        pe.initCause(e);
        throw pe;
    }

    protected class DoNothingPreparer implements Preparer {
        @Override
        public void prepare(PreparedStatement ps) {
            // do nothing
        }

        @Override
        public String getInfoString() {
            return null;
        }
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        try {
            JDBCUtil.execute("select 1 from CertificateData where fingerprint='XX'", new DoNothingPreparer(), getDataSource());
        } catch (Exception e) {
            log.error("Connection test failed: ", e);
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: " + e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ValidationAuthorityPublisher clone = new ValidationAuthorityPublisher();
        @SuppressWarnings("unchecked")
        HashMap<Object, Object> clonedata = (HashMap<Object, Object>) clone.saveData();

        Iterator<Object> i = (this.data.keySet()).iterator();
        while (i.hasNext()) {
            Object key = i.next();
            clonedata.put(key, this.data.get(key));
        }
        clone.loadData(clonedata);
        return clone;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }
}
