/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.log4j.Logger;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Data session bean for IncompleteIssuanceJournalData
 *
 * @see org.cesecore.certificates.ca.IncompleteIssuanceJournalCallbacks IncompleteIssuanceJournalCallbacks
 */
@Stateless
public class IncompleteIssuanceJournalDataSessionBean implements IncompleteIssuanceJournalDataSessionLocal {

    private static final Logger log = Logger.getLogger(IncompleteIssuanceJournalDataSessionBean.class);

    /** Number of rows to fetch at once */
    private static final int BATCH_SIZE = 100;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void addToJournal(final IncompletelyIssuedCertificateInfo info) {
        if (log.isDebugEnabled()) {
            log.debug("Adding certificate with CA ID " + info.getCaId()+ " and serial number " + info.getSerialNumber().toString(16) + " to IncompleteIssuanceJournalData");
        }
        entityManager.persist(new IncompleteIssuanceJournalData(info));
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeFromJournal(final int caId, final BigInteger serialNumber) {
        removeFromJournalInternal(caId, serialNumber);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void removeFromJournalNewTransaction(final int caId, final BigInteger serialNumber) {
        removeFromJournalInternal(caId, serialNumber);
    }

    private void removeFromJournalInternal(final int caId, final BigInteger serialNumber) {
        if (serialNumber == null) {
            log.debug("removeFromJournal: Serial number is null.");
            return;
        }
        final IncompleteIssuanceJournalData journalData = find(caId, serialNumber);
        if (journalData != null) {
            if (log.isDebugEnabled()) {
                log.debug("Removing certificate with CA ID " + caId + " and serial number " + serialNumber.toString(16) + " from IncompleteIssuanceJournalData");
            }
            entityManager.remove(journalData);
        } else if (log.isDebugEnabled()) {
            log.debug("Journal data unexpectedly disappeared for certificate, CA ID: " + caId + ", serial: 0x" + serialNumber.toString(16));
        }
    }

    @Override
    public boolean presentInJournal(int caId, BigInteger serialNumber) {
        boolean present = find(caId, serialNumber) != null;
        if (log.isDebugEnabled()) {
            log.debug("presentInJournal(" + caId + "," + serialNumber.toString(16) + ") = " + present);
        }
        return present;
    }

    private IncompleteIssuanceJournalData find(final int caId, final BigInteger serialNumber) {
        final TypedQuery<IncompleteIssuanceJournalData> query = entityManager.createQuery(
                "SELECT a FROM IncompleteIssuanceJournalData a WHERE a.serialNumberAndCaId=:serialNumberAndCaId", IncompleteIssuanceJournalData.class);
        query.setParameter("serialNumberAndCaId", IncompleteIssuanceJournalData.makePrimaryKey(caId, serialNumber));
        query.setMaxResults(1);
        for (final IncompleteIssuanceJournalData result : query.getResultList()) {
            return result;
        }
        return null;
    }

    @Override
    public List<IncompletelyIssuedCertificateInfo> getIncompleteIssuedCertsBatch(final long maxIssuanceTimeMillis) {
        final TypedQuery<IncompleteIssuanceJournalData> query = entityManager.createQuery(
                "SELECT a FROM IncompleteIssuanceJournalData a WHERE a.startTime < :maxStartTime", IncompleteIssuanceJournalData.class);
        query.setParameter("maxStartTime", new Date().getTime() - maxIssuanceTimeMillis);
        query.setMaxResults(BATCH_SIZE);
        final List<IncompletelyIssuedCertificateInfo> results = new ArrayList<>();
        for (final IncompleteIssuanceJournalData row : query.getResultList()) {
            results.add(new IncompletelyIssuedCertificateInfo(row.getCaId(), row.getSerialNumber(), row.getStartTime(), row.getDataMap()));
        }
        return results;
    }

}
