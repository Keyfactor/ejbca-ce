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
import java.util.List;

import javax.ejb.Local;

import org.cesecore.certificates.ca.IncompleteIssuanceJournalCallbacks;

/**
 * Data session for IncompleteIssuanceJournalData
 *
 * All methods are declared in IncompleteIssuanceJournalCallbacks
 *
 * @see org.cesecore.certificates.ca.IncompleteIssuanceJournalCallbacks IncompleteIssuanceJournalCallbacks
 */
@Local
public interface IncompleteIssuanceJournalDataSessionLocal extends IncompleteIssuanceJournalCallbacks {

    /**
     * Gets up to 100 incompletely issued certificates, that are older than 1 hour.
     * Those can safely be assumed to be failed issuances.
     *
     * @param maxIssuanceTimeMillis  Time until a certificate issuance is considered to have failed.
     * @return List with one entry per certificate, or an empty list if there are no more incompletely issued certificates.
     */
    List<IncompletelyIssuedCertificateInfo> getIncompleteIssuedCertsBatch(long maxIssuanceTimeMillis);

    /**
     * Checks if the given certificate is present in IncompleteIssuanceJournalData
     */
    boolean presentInJournal(int caId, BigInteger serialNumber);

}
