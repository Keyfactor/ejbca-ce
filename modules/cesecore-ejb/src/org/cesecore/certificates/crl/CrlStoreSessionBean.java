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

import com.keyfactor.util.CertTools;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.ValueExtractor;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs. CRLs are signed using
 * SignSessionBean.
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CrlStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlStoreSessionBean implements CrlStoreSessionLocal, CrlStoreSessionRemote {

    private static final Logger log = Logger.getLogger(CrlStoreSessionBean.class);

    private static final String CRL_DELETION_SEARCH_QUERY = "SELECT new org.cesecore.certificates.crl.CrlMetadataHolderDto("
            + "a.fingerprint, a.issuerDN, a.crlNumber, a.deltaCRLIndicator, a.nextUpdate) "
            + "FROM CRLData a WHERE a.issuerDN = :issuerDn "
            + "AND crlNumber < :maxCrlNumber "
            + "AND crlNumber <> :lastBaseCrlNumber "
            + "AND a.nextUpdate < :currentTime";

    /** Internal localization of logs and errors */
    protected static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    

    @Override
    public void storeCRL(final AuthenticationToken admin, final byte[] incrl, final String cafp, final int number, final String issuerDN, final int crlPartitionIndex,
            final Date thisUpdate, final Date nextUpdate, final int deltaCRLIndicator) throws CrlStoreException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL(" + cafp + ", " + number + ")");
        }
        // Check that user is authorized to the CA that issued this CRL
        String bcdn = CertTools.stringToBCDNString(issuerDN);
        int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);

        try {
            boolean deltaCRL = deltaCRLIndicator > 0;
            int lastNo = getLastCRLNumber(issuerDN, crlPartitionIndex, deltaCRL);
            if (number <= lastNo) {
                // There is already a CRL with this number, or a later one stored. Don't create duplicates
                final String msg = intres.getLocalizedMessage("store.errorstorecrlwrongnumber", Integer.valueOf(number), Integer.valueOf(lastNo), issuerDN);
                throw new CrlStoreException(msg);
            }
            CRLData data = new CRLData(incrl, number, crlPartitionIndex, issuerDN, thisUpdate, nextUpdate, cafp, deltaCRLIndicator);
            this.entityManager.persist(data);
            String msg = intres.getLocalizedMessage("store.storecrl", Integer.valueOf(number), data.getFingerprint(), data.getIssuerDN());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            logSession.log(EventTypes.CRL_STORED, EventStatus.SUCCESS, ModuleTypes.CRL, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("store.errorstorecrl", Integer.valueOf(number), issuerDN);
            log.error(msg, e);
            throw new CrlStoreException(e); // will rollback etc
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCRL()");
        }
    }
    
    /** @return the found entity instance or null if the entity does not exist */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLData findByFingerprint(String fingerprint) {
        return entityManager.find(CRLData.class, fingerprint);
    }
    
    /**
     * Find all CRLs issued by the given issuer.
     *
     * @param issuerDN the DN of the CRL issuer.
     * @return all CRLs for the given issuer.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<CRLData> findByIssuerDN(final String issuerDN) {
        final TypedQuery<CRLData> query = entityManager.createQuery("SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN", CRLData.class);
        query.setParameter("issuerDN", issuerDN);
        return query.getResultList();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<CrlMetadataHolderDto> findExpiredCrlByIssuerDn(String issuerDn, long maximumExpiredTime, int lastBaseCrlNumber,
            int lastDeltaCrlNumber, int maxNumberOfResults) {
        StringBuilder sqlBuilder = new StringBuilder(CRL_DELETION_SEARCH_QUERY);
        if (issuerDn != null) {
            sqlBuilder.append(" AND issuerDN = :issuerDn");
        }
        TypedQuery<CrlMetadataHolderDto> query = entityManager.createQuery(sqlBuilder.toString(),
                CrlMetadataHolderDto.class);
        query.setMaxResults(maxNumberOfResults);
        query.setParameter("issuerDn", issuerDn);
        query.setParameter("currentTime", maximumExpiredTime);
        query.setParameter("maxCrlNumber", Math.max(lastBaseCrlNumber, lastDeltaCrlNumber));
        query.setParameter("lastBaseCrlNumber", lastBaseCrlNumber);
        return query.getResultList();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getLastCRLInfo(final String issuerDn, final int crlPartitionIndex, final boolean deltaCRL) {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getLastCRLInfo(" + issuerDn + ", " + deltaCRL + ")");
            }
            final int crlNumber = getLastCRLNumber(issuerDn, crlPartitionIndex, deltaCRL);
            final CRLData data = findByIssuerDNAndCRLNumber(issuerDn, crlPartitionIndex, crlNumber);
            if (data == null) {
                if (deltaCRL && crlNumber == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("No delta CRL exists for CA with subject DN '" + issuerDn + "'.");
                    }
                } else if (crlNumber == 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("No CRL exists for CA with subject DN '" + issuerDn + "'.");
                    }
                } else {
                    log.error(getMessageWithPartitionIndex(crlPartitionIndex, "store.errorgetcrl", issuerDn, crlNumber));
                }
                return null;
            }
            return new CRLInfo(data);
        } catch (final Exception e) {
            log.info(intres.getLocalizedMessage("store.errorgetcrlinfo", issuerDn));
            throw new EJBException(e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<getLastCRLInfo()");
            }
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getLastCRLInfoLightWeight(final String issuerDn, final int crlPartitionIndex, final boolean deltaCRL) {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getLastCRLInfoLightWeight(" + issuerDn + ", " + deltaCRL + ")");
            }
            final int crlNumber = getLastCRLNumber(issuerDn, crlPartitionIndex, deltaCRL);
            if(crlNumber==0) {
                return null;
            }

            final List<Object[]> thisNextUpdateList = findThisUpdateNextUpdateByIssuerDNAndCRLNumber(issuerDn, crlPartitionIndex, crlNumber);

            if (thisNextUpdateList.isEmpty()) {
                return null;
            }
            
            // Check SQL result set mapping in CRLData class for explanation.
            final Object[] fields = thisNextUpdateList.get(0);
            final long thisUpdate = ValueExtractor.extractLongValue(fields[0]);
            final long nextUpdate = ValueExtractor.extractLongValue(fields[1]);

            return new CRLInfo(issuerDn, crlPartitionIndex, crlNumber, thisUpdate, nextUpdate);
        } catch (final Exception e) {
            log.info(intres.getLocalizedMessage("store.errorgetcrlinfo", issuerDn));
            throw new EJBException(e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<getLastCRLInfoLightWeight()");
            }
        }
    }
    
    /**
     * @return true if at least one CRL exists for the given CA.
     */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean crlExistsForCa(final String issuerDn) {
        final Query query = entityManager
                .createQuery("SELECT a.crlNumber FROM CRLData a WHERE a.issuerDN=:issuerDN");
        query.setParameter("issuerDN", issuerDn).setMaxResults(1);
        return !query.getResultList().isEmpty();
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getCRLInfo(final String fingerprint) {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getCRLInfo(" + fingerprint + ")");
            }
            final CRLData data = findByFingerprint(fingerprint);
            if (data == null) {
                if (log.isDebugEnabled()) {
                    log.debug("No CRL exists with fingerprint '" + fingerprint + "'.");
                }
                log.info(intres.getLocalizedMessage("store.errorgetcrl", fingerprint, 0));
                return null;
            }
            return new CRLInfo(data);
        } catch (final Exception e) {
            log.info(intres.getLocalizedMessage("store.errorgetcrlinfo", fingerprint));
            throw new EJBException(e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<getCRLInfo()");
            }
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public int getLastCRLNumber(final String issuerdn, final int crlPartitionIndex, final boolean deltaCRL) {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCRLNumber(" + issuerdn + ", " + deltaCRL + ")");
        }
        int maxnumber = 0;
        Integer result = findHighestCRLNumber(issuerdn, crlPartitionIndex, deltaCRL);
        if (result != null) {
            maxnumber = result.intValue();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getLastCRLNumber(" + maxnumber + ")");
        }
        return maxnumber;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Date getCrlExpireDate(final String issuerDn, final int crlPartitionIndex, final boolean deltaCRL) {

        if (log.isTraceEnabled()) {
            log.trace(">getCrlExpireDate(" + issuerDn + ", " + deltaCRL + ")");
        }
        
        final int crlNumber = getLastCRLNumber(issuerDn, crlPartitionIndex, deltaCRL);

        final Long nextUpdate = findNextUpdateByIssuerDNAndCRLNumber(issuerDn, crlPartitionIndex, crlNumber);

        if (nextUpdate == null) {
            return null;
        }
        
        if (log.isTraceEnabled()) {
            log.trace("<getCrlExpireDate()");
        }
        return new Date(nextUpdate.longValue());
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public byte[] getLastCRL(final String issuerdn, final int crlPartitionIndex, boolean deltaCRL) {
        if (log.isTraceEnabled()) {
            log.trace(">getLastCRL(" + issuerdn + ", " + deltaCRL + ")");
        }
        int maxnumber = 0;
        try {
            maxnumber = getLastCRLNumber(issuerdn, crlPartitionIndex, deltaCRL);
            byte[] crlbytes = null;
            final CRLData crlData = findByIssuerDNAndCRLNumber(issuerdn, crlPartitionIndex, maxnumber);
            if (Objects.nonNull(crlData)) {
                crlbytes = crlData.getCRLBytes();
                if (crlbytes != null) {
                    final String msg = getMessageWithPartitionIndex(crlPartitionIndex, "store.getcrl", issuerdn, Integer.valueOf(maxnumber));
                    log.info(msg);
                    return crlbytes;
                }
            }
        } catch (Exception e) {
            final String msg = getMessageWithPartitionIndex(crlPartitionIndex, "store.errorgetcrl", issuerdn);
            log.info(msg);
            throw new EJBException(e);
        }
        final String msg = getMessageWithPartitionIndex(crlPartitionIndex, "store.errorgetcrl", issuerdn, Integer.valueOf(maxnumber));
        log.info(msg);
        if (log.isTraceEnabled()) {
            log.trace("<getLastCRL()");
        }
        return null;
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public byte[] getCRL(final String issuerdn, final int crlPartitionIndex, final int crlNumber) {
        if (log.isTraceEnabled()) {
            log.trace(">getCRL(" + issuerdn + ", " + crlNumber + ")");
        }
        byte[] crlbytes = null;
        final CRLData crlData = findByIssuerDNAndCRLNumber(issuerdn, crlPartitionIndex, crlNumber);
        if (Objects.nonNull(crlData)) {
            crlbytes = crlData.getCRLBytes();
            if (crlbytes != null) {
                final String msg = getMessageWithPartitionIndex(crlPartitionIndex, "store.getcrl", issuerdn, Integer.valueOf(crlNumber));
                log.info(msg);
                return crlbytes;
            }
        }
        final String msg = getMessageWithPartitionIndex(crlPartitionIndex, "store.errorgetcrl", issuerdn, Integer.valueOf(crlNumber));
        log.info(msg);
        if (log.isTraceEnabled()) {
            log.trace("<getCRL()");
        }
        return null;
    }
    
    @Override
    public void removeByIssuerDN(final String issuerDN) {
        List<CRLData> crls = findByIssuerDN(issuerDN);
        for(CRLData crlData : crls) {
            this.entityManager.remove(crlData);
        }
    }

    @Override
    public void delete(CrlMetadataHolderDto crlMetadata, AuthenticationToken adminForLogging) {
        String fingerprint = crlMetadata.getFingerprint();
        if (crlMetadata.getNextUpdate() > System.currentTimeMillis()) {
            throw new IllegalStateException("CRL with the fingerprint=" + fingerprint + " is not yet expired");
        }
        final Query query = entityManager.createQuery("DELETE FROM CRLData c WHERE c.fingerprint = :fingerprint");
        query.setParameter("fingerprint", fingerprint);
        query.executeUpdate();

        final String caIdString = (crlMetadata.getIssuerDN() != null ? String.valueOf(crlMetadata.getIssuerDN().hashCode()) : null);
        final String detailsMsg = InternalResources.getInstance().getLocalizedMessage("store.deleteexpiredcrl",
                crlMetadata.getFingerprint(), caIdString);
        logSession.log(EventTypes.CRL_CLEANUP, EventStatus.SUCCESS, ModuleTypes.CRL, ServiceTypes.CORE, adminForLogging.toString(),
                caIdString, crlMetadata.getFingerprint(), crlMetadata.getIssuerDN(), detailsMsg);
    }

    /**
     * Get the highest CRL number issued by the given issuer.
     *
     * @param issuerDN the DN of the CRL issuer.
     * @param crlPartitionIndex CRL partition index, or {@link CertificateConstants#NO_CRL_PARTITION} if not using CRL partitioning.
     * @param deltaCRL false to fetch the latest base CRL, or true to fetch the latest delta CRL.
     * @return the highest CRL number or null if no CRL for the specified issuer exists.
     */
    private Integer findHighestCRLNumber(final String issuerDN, final int crlPartitionIndex, boolean deltaCRL) {
        if (deltaCRL) {
            final String deltaCrlCrlIndicatorClause = "AND a.deltaCRLIndicator > 0";
            return findHighestCRLNumber(issuerDN, crlPartitionIndex, deltaCrlCrlIndicatorClause);
        } else {
            final String nonDeltaCrlCrlIndicatorClause = "AND a.deltaCRLIndicator = -1";
            return findHighestCRLNumber(issuerDN, crlPartitionIndex, nonDeltaCrlCrlIndicatorClause);
        }
    }

    private Integer findHighestCRLNumber(final String issuerDN, final int crlPartitionIndex, String deltaCrlIndicatorClause) {
        final Query query = entityManager.createQuery(
                "SELECT MAX(a.crlNumber) FROM CRLData a WHERE a.issuerDN=:issuerDN "
                        + deltaCrlIndicatorClause + " AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex));
        query.setParameter("issuerDN", issuerDN);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return QueryResultWrapper.getSingleResult(query);
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
     * Find a CRL issued by the given issuer, with the given CRL partition index and CRL number.
     *
     * @param issuerDN the DN of the CRL issuer.
     * @param crlPartitionIndex CRL partition index, or {@link CertificateConstants#NO_CRL_PARTITION} if not using CRL partitioning.
     * @param crlNumber the CRL number.
     * @return the found entity instance or null if the entity does not exist.
     */
    private CRLData findByIssuerDNAndCRLNumber(final String issuerDN, final int crlPartitionIndex,
            final int crlNumber) {
        final Query query = entityManager.createQuery("SELECT a FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                + getCrlPartitionIndexCondition(crlPartitionIndex), CRLData.class);
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return (CRLData) QueryResultWrapper.getSingleResult(query);
    }

    private String getMessageWithPartitionIndex(final int crlPartitionIndex, final String messageKey, final Object... params) {
        final StringBuilder sb = new StringBuilder();
        sb.append(intres.getLocalizedMessage(messageKey, params));
        if (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION) {
            sb.append(' ');
            sb.append(intres.getLocalizedMessage("store.crlpartition", crlPartitionIndex));
        }
        return sb.toString();
    }
    
    /**
     * Find a CRL's nextUpdate value by the given issuer, partition index and number.
     * 
     * @param issuerDN
     * @param crlPartitionIndex
     * @param crlNumber
     * @return
     */
    private Long findNextUpdateByIssuerDNAndCRLNumber(final String issuerDN,
            final int crlPartitionIndex, final int crlNumber) {
        final Query query = entityManager
                .createQuery("SELECT a.nextUpdate FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex));
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return (Long) QueryResultWrapper.getSingleResult(query);
    }
    
    /**
     * Find a CRL's thisUpdate value by the given issuer, partition index and number.
     * 
     * @param issuerDN
     * @param crlPartitionIndex
     * @param crlNumber
     * @return
     */
    @SuppressWarnings("unchecked")
    private List<Object[]> findThisUpdateNextUpdateByIssuerDNAndCRLNumber(final String issuerDN,
            final int crlPartitionIndex, final int crlNumber) {
        final Query query = entityManager
                .createNativeQuery("SELECT a.thisUpdate, a.nextUpdate FROM CRLData a WHERE a.issuerDN=:issuerDN AND a.crlNumber=:crlNumber AND "
                        + getCrlPartitionIndexCondition(crlPartitionIndex), "ThisUpdateNextUpdateSelectQuery");
        query.setParameter("issuerDN", issuerDN);
        query.setParameter("crlNumber", crlNumber);
        query.setMaxResults(1);
        if (crlPartitionIndex > 0) {
            query.setParameter("crlPartitionIndex", crlPartitionIndex);
        }
        return query.getResultList();
    }
    

    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }

}
