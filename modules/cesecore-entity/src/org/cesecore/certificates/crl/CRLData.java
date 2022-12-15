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
package org.cesecore.certificates.crl;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.dbprotection.DatabaseProtectionException;
import org.cesecore.dbprotection.ProtectedData;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.QueryResultWrapper;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.PostLoad;
import javax.persistence.PrePersist;
import javax.persistence.PreUpdate;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;
import javax.persistence.TypedQuery;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.List;

/**
 * Representation of a CRL.
 */
@Entity
@Table(name = "CRLData")
public class CRLData extends ProtectedData implements Serializable {

    private static final long serialVersionUID = 5542295476157001912L;

    private static final Logger log = Logger.getLogger(CRLData.class);

    private static final int LATEST_PROTECT_VERSION = 2;

    private int cRLNumber;
    private int deltaCRLIndicator;
    private Integer crlPartitionIndex; // Since EJBCA 7.1.0
    private String issuerDN;
    private String fingerprint;
    private String cAFingerprint;
    private long thisUpdate;
    private long nextUpdate;
    private String base64Crl; 
    private int rowVersion = 0;
    private String rowProtection;

    /**
     * Entity holding info about a CRL. Create by sending in the CRL, which extracts (from the crl) fingerprint (primary key), CRLNumber, issuerDN,
     * thisUpdate, nextUpdate. CAFingerprint is the hash of the CA certificate.
     * 
     * @param incrl
     *            the (X509)CRL to be stored in the database.
     * @param number
     *            monotonically increasing CRL number
     * @param crlPartitionIndex CRL partition index, or {@link CertificateConstants#NO_CRL_PARTITION} if not using CRL partitioning.
     * @param deltaCRLIndicator
     *            -1 for a normal CRL and 1 for a deltaCRL
     */
    public CRLData(byte[] incrl, int number, int crlPartitionIndex, String issuerDN, Date thisUpdate, Date nextUpdate, String cafingerprint, int deltaCRLIndicator) {
        String b64Crl = new String(Base64.encode(incrl));
        setBase64Crl(b64Crl);
        String fp = CertTools.getFingerprintAsString(incrl);
        setFingerprint(fp);
        // Make sure names are always looking the same
        String issuer = CertTools.stringToBCDNString(issuerDN);
        setIssuerDN(issuer);
        if (log.isDebugEnabled()) {
            log.debug("Creating crldata, fp=" + fp + ", issuer=" + issuer + ", crlNumber=" + number + ", crlPartitionIndex="
                    + crlPartitionIndex + ", deltaCRLIndicator=" + deltaCRLIndicator);
        }
        setCaFingerprint(cafingerprint);
        setCrlNumber(number);
        setThisUpdate(thisUpdate);
        setNextUpdate(nextUpdate);
        setDeltaCRLIndicator(deltaCRLIndicator);
        setCrlPartitionIndex(crlPartitionIndex);
    }

    public CRLData() {
    }

    // @Column
    public int getCrlNumber() {
        return cRLNumber;
    }

    public void setCrlNumber(int cRLNumber) {
        this.cRLNumber = cRLNumber;
    }

    // @Column
    public int getDeltaCRLIndicator() {
        return deltaCRLIndicator;
    }

    public void setDeltaCRLIndicator(int deltaCRLIndicator) {
        this.deltaCRLIndicator = deltaCRLIndicator;
    }

    /**
     *  Get the CRL partition index for this row.
     *
     *  <p>
     *  <b>Implementation note</b>
     *  <p>{@link CertificateConstants#NO_CRL_PARTITION} is represented with -1 to avoid NULLs being
     *  stored in some databases.
     *
     *  @since EJBCA 7.1.0
     *  @return the CRL partition index, or -1 if CRL partitioning is not being used.
     */
    // @Column
    public int getCrlPartitionIndex() {
        return crlPartitionIndex == null || crlPartitionIndex == CertificateConstants.NO_CRL_PARTITION
                ? -1
                : crlPartitionIndex;
    }

    /**
     * Set the CRL partition index for this row.
     *
     * @since EJBCA 7.1.0
     * @param crlPartitionIndex the CRL partition index to set.
     */
    public void setCrlPartitionIndex(final Integer crlPartitionIndex) {
        this.crlPartitionIndex = crlPartitionIndex;
    }

    // @Column
    public String getIssuerDN() {
        return issuerDN;
    }

    /**
     * Use setIssuer instead
     * 
     * @see #setIssuer(String)
     */
    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    // @Id @Column
    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    // @Column
    public String getCaFingerprint() {
        return cAFingerprint;
    }

    public void setCaFingerprint(String cAFingerprint) {
        this.cAFingerprint = cAFingerprint;
    }

    // @Column
    public long getThisUpdate() {
        return thisUpdate;
    }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     */
    public void setThisUpdate(long thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    // @Column
    public long getNextUpdate() {
        return nextUpdate;
    }

    /**
     * Date formated as seconds since 1970 (== Date.getTime())
     */
    public void setNextUpdate(long nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    // @Column @Lob
    public String getBase64Crl() {
        return base64Crl;
    }

    public void setBase64Crl(String base64Crl) {
        this.base64Crl = base64Crl;
    }

    // @Version @Column
    public int getRowVersion() {
        return rowVersion;
    }

    public void setRowVersion(int rowVersion) {
        this.rowVersion = rowVersion;
    }

    // @Column @Lob
    @Override
    public String getRowProtection() {
        return rowProtection;
    }

    @Override
    public void setRowProtection(String rowProtection) {
        this.rowProtection = rowProtection;
    }

    //
    // Public methods used to help us manage CRLs
    //
    @Transient
    public X509CRL getCRL() {
        try {
            return CertTools.getCRLfromByteArray(Base64.decode(this.base64Crl.getBytes()));
        } catch (CRLException ce) {
            log.error("Can't decode CRL.", ce);
        }
        return null;
    }

    public void setCRL(X509CRL incrl) {
        try {
            String b64Crl = new String(Base64.encode((incrl).getEncoded()));
            setBase64Crl(b64Crl);
        } catch (CRLException ce) {
            log.error("Can't extract DER encoded CRL.", ce);
        }
    }

    @Transient
    public byte[] getCRLBytes() {
        return Base64.decode(this.base64Crl.getBytes());
    }

    public void setIssuer(String dn) {
        setIssuerDN(CertTools.stringToBCDNString(dn));
    }

    public void setThisUpdate(Date thisUpdate) {
        if (thisUpdate == null) {
            setThisUpdate(-1L);
        } else {
            setThisUpdate(thisUpdate.getTime());
        }
    }

    public void setNextUpdate(Date nextUpdate) {
        if (nextUpdate == null) {
            setNextUpdate(-1L);
        } else {
            setNextUpdate(nextUpdate.getTime());
        }
    }

    //
    // Search functions.
    //

    /** @return the found entity instance or null if the entity does not exist */
    public static CRLData findByFingerprint(EntityManager entityManager, String fingerprint) {
        return entityManager.find(CRLData.class, fingerprint);
    }

    /**
     * Find a CRL issued by the given issuer, with the given CRL partition index and CRL number.
     *
     * @param entityManager an entity manager for reading from CRLData.
     * @param issuerDN the DN of the CRL issuer.
     * @param crlPartitionIndex CRL partition index, or {@link CertificateConstants#NO_CRL_PARTITION} if not using CRL partitioning.
     * @param crlNumber the CRL number.
     * @return the found entity instance or null if the entity does not exist.
     */
    public static CRLData findByIssuerDNAndCRLNumber(final EntityManager entityManager, final String issuerDN, final int crlPartitionIndex,
            final int crlNumber) {
        final Query query = entityManager.createNativeQuery("SELECT * FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                + getCrlPartitionIndexCondition(crlPartitionIndex), CRLData.class);
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return QueryResultWrapper.getSingleResult(query);
    }

    public static String findBase64CrlByIssuerDNAndCRLNumber(final EntityManager entityManager, final String issuerDN, final int crlPartitionIndex,
            final int crlNumber) {
        final Query query = entityManager
                .createNativeQuery("SELECT base64Crl FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex));
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return QueryResultWrapper.getSingleResult(query);
    }
    
    
    /**
     * Find a CRL's thisUpdate value by the given issuer, partition index and number.
     * 
     * @param entityManager
     * @param issuerDN
     * @param crlPartitionIndex
     * @param crlNumber
     * @return
     */
    public static BigInteger findThisUpdateByIssuerDNAndCRLNumber(final EntityManager entityManager, final String issuerDN,
            final int crlPartitionIndex, final int crlNumber) {
        final Query query = entityManager
                .createNativeQuery("SELECT thisUpdate FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex));
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return QueryResultWrapper.getSingleResult(query);
    }
    
    /**
     * Find a CRL's nextUpdate value by the given issuer, partition index and number.
     * 
     * @param entityManager
     * @param issuerDN
     * @param crlPartitionIndex
     * @param crlNumber
     * @return
     */
    public static BigInteger findNextUpdateByIssuerDNAndCRLNumber(final EntityManager entityManager, final String issuerDN,
            final int crlPartitionIndex, final int crlNumber) {
        final Query query = entityManager
                .createNativeQuery("SELECT nextUpdate FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex));
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return QueryResultWrapper.getSingleResult(query);
    }
    
    /**
     * Find all CRLs issued by the given issuer.
     *
     * @param entityManager an entity manager for reading from CRLData.
     * @param issuerDN the DN of the CRL issuer.
     * @return all CRLs for the given issuer.
     */
    public static List<CRLData> findByIssuerDN(final EntityManager entityManager, final String issuerDN) {
        final TypedQuery<CRLData> query = entityManager.createQuery("SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN", CRLData.class);
        query.setParameter("issuerDN", issuerDN);
        return query.getResultList();
    }

    /**
     * Get the highest CRL number issued by the given issuer.
     *
     * @param issuerDN the DN of the CRL issuer.
     * @param crlPartitionIndex CRL partition index, or {@link CertificateConstants#NO_CRL_PARTITION} if not using CRL partitioning.
     * @param deltaCRL false to fetch the latest base CRL, or true to fetch the latest delta CRL.
     * @return the highest CRL number or null if no CRL for the specified issuer exists.
     */
    public static Integer findHighestCRLNumber(final EntityManager entityManager, final String issuerDN, final int crlPartitionIndex, boolean deltaCRL) {
        if (deltaCRL) {
            final Query query = entityManager.createQuery(
                    "SELECT MAX(a.crlNumber) FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.deltaCRLIndicator>0 AND "
                            + getCrlPartitionIndexCondition(crlPartitionIndex));
            query.setParameter("issuerDN", issuerDN);
            query.setMaxResults(1);
            if (crlPartitionIndex > 0) {
                query.setParameter("crlPartitionIndex", crlPartitionIndex);
            }
            return (Integer) QueryResultWrapper.getSingleResult(query);
        } else {
            final Query query = entityManager.createQuery(
                    "SELECT MAX(a.crlNumber) FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.deltaCRLIndicator=-1 AND "
                            + getCrlPartitionIndexCondition(crlPartitionIndex));
            query.setParameter("issuerDN", issuerDN);
            query.setMaxResults(1);
            if (crlPartitionIndex > 0) {
                query.setParameter("crlPartitionIndex", crlPartitionIndex);
            }
            return QueryResultWrapper.getSingleResult(query);
        }
    }

    /**
     * Get a JPQL query condition for a given CRL partition index.
     *
     * <p>If the crlPartitionIndex parameter indicates that partitioned CRLs are used (i.e. crlPartitionIndex > 0)
     * then simply return:
     * <pre>
     *     "a.crlPartitionIndex=:crlPartitionIndex"
     * </pre>
     *
     * <p>If the crlPartitionIndex parameter indicates that partitioned CRLs are <i>not</i> used (i.e. crlPartitionIndex =
     * {@link CertificateConstants#NO_CRL_PARTITION}),
     * a more elaborate query condition is needed to keep compatibility with data created by EJBCA <7.4. The CRL partition index
     * in the database can either be {@link CertificateConstants#NO_CRL_PARTITION}, NULL or -1. Thus, for this case return:
     * <pre>
     *     "a.crlPartitionIndex=-1 OR a.crlPartitionIndex=0 OR a.crlPartitionIndex IS NULL"
     * </pre>
     *
     * @param crlPartitionIndex the CRL partition index to use in the query condition.
     * @return a JPQL query condition to use in the <code>WHERE</code> clause when querying for CRLs.
     */
    private static String getCrlPartitionIndexCondition(final int crlPartitionIndex) {
        if (crlPartitionIndex > 0) {
            // Get a partitioned CRL with the specified partition index
            return "a.crlPartitionIndex=:crlPartitionIndex";
        }
        // Get a non-partitioned CRL
        // Old data is represented with 0 or NULL. New data uses -1 instead.
        return "(a.crlPartitionIndex=-1 OR a.crlPartitionIndex=0 OR a.crlPartitionIndex IS NULL)";
    }

    /**
     * @return true if at least one CRL exists for the given CA.
     */
    public static boolean crlExistsForCa(final EntityManager entityManager, final String issuerDn) {
        final Query query = entityManager
                .createQuery("SELECT a.crlNumber FROM CRLData a WHERE a.issuerDN=:issuerDN");
        query.setParameter("issuerDN", issuerDn).setMaxResults(1);
        return !query.getResultList().isEmpty();
    }

    //
    // Start Database integrity protection methods
    //

    @Transient
    @Override
    protected String getProtectString(final int version) {
    	final ProtectionStringBuilder build = new ProtectionStringBuilder(3000);
        // What is important to protect here is the data that we define
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getFingerprint()).append(getCrlNumber()).append(getDeltaCRLIndicator()).append(getIssuerDN()).append(getCaFingerprint())
                .append(getThisUpdate()).append(getNextUpdate()).append(getBase64Crl());
        if (version >= 2) {
            // CRL Partition Index added in EJBCA 7.1.0
            // Build the database protection string using CertificateConstants.NO_CRL_PARTITION instead of -1.
            build.append(getCrlPartitionIndex() == -1 ? 0 : getCrlPartitionIndex());
        }
        return build.toString();
    }

    @Transient
    @Override
    protected int getProtectVersion() {
        return LATEST_PROTECT_VERSION;
    }

    @PrePersist
    @PreUpdate
    @Override
    protected void protectData() throws DatabaseProtectionException {
        super.protectData();
    }

    @PostLoad
    @Override
    protected void verifyData() throws DatabaseProtectionException {
        super.verifyData();
    }

    @Override
    @Transient
    protected String getRowId() {
        return getFingerprint();
    }
    //
    // End Database integrity protection methods
    //

}
