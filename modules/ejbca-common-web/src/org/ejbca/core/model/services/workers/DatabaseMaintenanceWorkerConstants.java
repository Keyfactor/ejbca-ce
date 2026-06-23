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
 
 
package org.ejbca.core.model.services.workers;

import org.ejbca.core.model.services.IWorker;

public final class DatabaseMaintenanceWorkerConstants {

    public static final String WORKER_CLASS = "org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker";
    public static final String DEFAULT_DELAY_TIMEUNIT = IWorker.UNIT_DAYS;
    public static final int DEFAULT_DELAY_TIMEVALUE = 30;
    public static final String DEFAULT_REVOKE_DELAY_TIMEUNIT = IWorker.UNIT_HOURS;
    public static final int DEFAULT_REVOKE_DELAY_TIMEVALUE = 1;
    public static final int DEFAULT_BATCH_SIZE = 100;
    /** Default reason filter for the "Delete revoked certificates" mode — RFC 5280 SUPERSEDED. */
    public static final String DEFAULT_REVOCATION_REASONS = "SUPERSEDED";

    // --- Certificate deletion mode (radio) ---------------------------------
    /** Property key for the mutually-exclusive cert-deletion mode. */
    public static final String PROP_CERT_DELETION_MODE = "certDeletionMode";
    /** No cert deletion — worker only operates on CRLs (if enabled). */
    public static final String MODE_NONE = "NONE";
    /** Delete any cert past its notAfter (catches E + R lifecycle buckets). */
    public static final String MODE_EXPIRED = "EXPIRED";
    /** Delete any revoked-by-reason cert regardless of expiry (catches r + R lifecycle buckets). */
    public static final String MODE_REVOKED = "REVOKED";
    /** Default mode for a fresh worker — operator opts in explicitly. */
    public static final String DEFAULT_CERT_DELETION_MODE = MODE_NONE;

    /** Delay between a certificate's notAfter and when MODE_EXPIRED considers it eligible. */
    public static final String PROP_DELAY_TIMEUNIT = "delayTimeUnit";
    public static final String PROP_DELAY_TIMEVALUE = "delayTimeValue";
    /** Delay between a certificate's revocation timestamp and when MODE_REVOKED considers it eligible. */
    public static final String PROP_REVOKE_DELAY_TIMEUNIT = "revokeDelayTimeUnit";
    public static final String PROP_REVOKE_DELAY_TIMEVALUE = "revokeDelayTimeValue";

    // --- Legacy boolean flags ---------------------------------------------
    // Kept for backward compatibility with pre-radio worker configurations
    // (e.g. EE installations with deleteExpiredCertificates=true). The bean
    // derives certDeletionMode from these when PROP_CERT_DELETION_MODE is
    // absent. Going forward, PROP_CERT_DELETION_MODE is the source of truth.
    public static final String PROP_DELETE_EXPIRED_CERTIFICATES = "deleteExpiredCertificates";
    public static final String PROP_DELETE_REVOKED_CERTIFICATES = "deleteRevokedCertificates";

    /** CRL-side cleanup (independent of cert-deletion mode). */
    public static final String PROP_DELETE_EXPIRED_CRLS = "deleteExpiredCrls";
    /** Comma-separated RFC 5280 reason names (e.g. {@code "SUPERSEDED,CESSATION_OF_OPERATION"}) used by MODE_REVOKED. */
    public static final String PROP_REVOCATION_REASONS = "revocationReasons";
    public static final String PROP_BATCH_SIZE = "batchSize";

    private DatabaseMaintenanceWorkerConstants() {
    }
}
