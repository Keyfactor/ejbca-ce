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
package org.cesecore.certificates.ca;

import java.math.BigInteger;

import org.cesecore.certificates.certificate.IncompletelyIssuedCertificateInfo;

/**
 * Callback to add certificates to the "incomplete issuance journal", which is used to revoke
 * incompletely issued certificates. This happens when a rollback (including database failures or power outages) happens
 * after a certificate has been published externally. That can happen in these two cases:
 * <ol>
 * <li>When only issuance of the pre-certificate succeeds, but not issuance/publishing of the final certificate
 * <li>When publishing succeeds with one publisher, but direct publishing with another publisher fails and triggers a rollback.
 * </ol>
 * It is safe to skip journaling if <strong>both</strong> of the following conditions are met:
 * <ol>
 * <li>Certificate transparency is <strong>not</strong> enabled.
 * <li>There is <strong>no</strong> direct publishing, except for MultiGroupPublishers which don't contain publishers with direct publishing.
 * </ol>
 */
public interface IncompleteIssuanceJournalCallbacks {

    /**
     * Adds a certificate to the "incomplete issuance journal". This should be called when a certificate
     * is being issued, but may get published before the transaction succeeds.
     *
     * @param info Information about certificate. The certificate should not have been persisted yet.
     */
    void addToJournal(final IncompletelyIssuedCertificateInfo info);

    /**
     * Removes a certificate from the "incomplete issuance journal". This should be called after successful issuance.
     *
     * @param caId CA ID
     * @param serialNumber Serial number of certificate (now present in CertificateData)
     */
    void removeFromJournal(int caId, BigInteger serialNumber);

    /**
     * @see #removeFromJournal
     */
    void removeFromJournalNewTransaction(int caId, BigInteger serialNumber);

}
