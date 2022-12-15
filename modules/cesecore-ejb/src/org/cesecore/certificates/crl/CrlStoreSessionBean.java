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

import org.apache.commons.lang3.StringUtils;
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
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import java.math.BigInteger;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs. CRLs are signed using
 * SignSessionBean.
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CrlStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlStoreSessionBean implements CrlStoreSessionLocal, CrlStoreSessionRemote {

    private static final Logger log = Logger.getLogger(CrlStoreSessionBean.class);

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
            final String base64CrlString = CRLData.findBase64CrlByIssuerDNAndCRLNumber(entityManager, issuerdn, crlPartitionIndex, maxnumber);
            if (StringUtils.isNotBlank(base64CrlString)) {
                crlbytes = Base64.decode(base64CrlString.getBytes());
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
        final String base64CrlString = CRLData.findBase64CrlByIssuerDNAndCRLNumber(entityManager, issuerdn, crlPartitionIndex, crlNumber);
        if (StringUtils.isNotBlank(base64CrlString)) {
            crlbytes = Base64.decode(base64CrlString.getBytes());
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
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CRLInfo getLastCRLInfo(final String issuerDn, final int crlPartitionIndex, final boolean deltaCRL) {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getLastCRLInfo(" + issuerDn + ", " + deltaCRL + ")");
            }
            final int crlNumber = getLastCRLNumber(issuerDn, crlPartitionIndex, deltaCRL);
            final CRLData data = CRLData.findByIssuerDNAndCRLNumber(entityManager, issuerDn, crlPartitionIndex, crlNumber);
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

            final BigInteger thisUpdate = CRLData.findThisUpdateByIssuerDNAndCRLNumber(entityManager, issuerDn, crlPartitionIndex, crlNumber);
            final BigInteger nextUpdate = CRLData.findNextUpdateByIssuerDNAndCRLNumber(entityManager, issuerDn, crlPartitionIndex, crlNumber);

            if (thisUpdate == null || nextUpdate == null) {
                return null;
            }

            return new CRLInfo(issuerDn, crlPartitionIndex, crlNumber, thisUpdate.longValue(), nextUpdate.longValue());
        } catch (final Exception e) {
            log.info(intres.getLocalizedMessage("store.errorgetcrlinfo", issuerDn));
            throw new EJBException(e);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<getLastCRLInfoLightWeight()");
            }
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Date getCrlExpireDate(final String issuerDn, final int crlPartitionIndex, final boolean deltaCRL) {

        if (log.isTraceEnabled()) {
            log.trace(">getCrlExpireDate(" + issuerDn + ", " + deltaCRL + ")");
        }
        
        final int crlNumber = getLastCRLNumber(issuerDn, crlPartitionIndex, deltaCRL);

        final BigInteger nextUpdate = CRLData.findNextUpdateByIssuerDNAndCRLNumber(entityManager, issuerDn, crlPartitionIndex, crlNumber);

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
    public CRLInfo getCRLInfo(final String fingerprint) {
        try {
            if (log.isTraceEnabled()) {
                log.trace(">getCRLInfo(" + fingerprint + ")");
            }
            final CRLData data = CRLData.findByFingerprint(entityManager, fingerprint);
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
        Integer result = CRLData.findHighestCRLNumber(entityManager, issuerdn, crlPartitionIndex, deltaCRL);
        if (result != null) {
            maxnumber = result.intValue();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getLastCRLNumber(" + maxnumber + ")");
        }
        return maxnumber;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean crlExistsForCa(final String issuerDn) {
        return CRLData.crlExistsForCa(entityManager, issuerDn);
    }

    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
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

}
