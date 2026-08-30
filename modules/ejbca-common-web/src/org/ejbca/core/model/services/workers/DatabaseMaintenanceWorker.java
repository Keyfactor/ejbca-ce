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

import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CrlMetadataHolderDto;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * JohnB: Database Maintenance Worker — periodic cleanup of certificate and CRL rows.
 *
 * <p>The cert-side cleanup is controlled by a three-way mutually-exclusive
 * radio of deletion modes
 * ({@link DatabaseMaintenanceWorkerConstants#PROP_CERT_DELETION_MODE}):
 *
 * <ul>
 *   <li>{@link DatabaseMaintenanceWorkerConstants#MODE_EXPIRED} —
 *       default operational mode. Sweeps any cert past its
 *       {@code notAfter} regardless of revocation status. Filter clause:
 *       {@code expireDate < now − delayAfterExpiration} (delay from
 *       {@link DatabaseMaintenanceWorkerConstants#PROP_DELAY_TIMEUNIT} /
 *       {@link DatabaseMaintenanceWorkerConstants#PROP_DELAY_TIMEVALUE}).
 *       Catches the {@code E} (naturally expired) and {@code R}
 *       (revoked-and-expired) lifecycle buckets.</li>
 *   <li>{@link DatabaseMaintenanceWorkerConstants#MODE_REVOKED} —
 *       cleanup mode for accumulated revoked-by-reason zombies. Sweeps
 *       any cert whose {@code revocationReason} is in the operator-selected
 *       set ({@link DatabaseMaintenanceWorkerConstants#PROP_REVOCATION_REASONS}),
 *       regardless of expiry. Filter clause:
 *       {@code status IN (REVOKED, ARCHIVED) AND revocationReason IN :reasons
 *       AND revocationDate < now − delayAfterRevocation} (revoke-delay from
 *       {@link DatabaseMaintenanceWorkerConstants#PROP_REVOKE_DELAY_TIMEUNIT} /
 *       {@link DatabaseMaintenanceWorkerConstants#PROP_REVOKE_DELAY_TIMEVALUE}).
 *       Catches the {@code r} (revoked-but-not-yet-expired) and
 *       {@code R} (revoked-and-expired, including the ARCHIVED
 *       {@code status=60} substate) lifecycle buckets — the widened
 *       {@code status IN (REVOKED, ARCHIVED)} clause vs the older
 *       {@code status = REVOKED} formulation is the critical design fix
 *       that prevents rows from escaping the sweep once EJBCA's
 *       post-expiry housekeeping has transitioned them from
 *       {@code status=40} to {@code status=60}.</li>
 *   <li>{@link DatabaseMaintenanceWorkerConstants#MODE_NONE} — safety
 *       default for fresh workers. Skips all cert-side work; only the
 *       independent CRL sweep runs if its checkbox is enabled.</li>
 * </ul>
 *
 * <p>An operator who wants OR-of-modes semantics (e.g. <em>"reap
 * naturally-expired rows AND, separately, reap accumulated
 * SUPERSEDED-revoked zombies"</em>) configures multiple worker entries on
 * the Manage Services page — one entry per mode. EJBCA's service scheduler
 * already serialises by worker, so stacked workers are operationally cheap.
 *
 * <p>Backward compatibility for pre-radio configurations is handled by
 * {@link #resolveCertDeletionMode()}: if {@code PROP_CERT_DELETION_MODE}
 * is absent (legacy config from an EE worker bag), the mode is derived
 * from the legacy
 * {@link DatabaseMaintenanceWorkerConstants#PROP_DELETE_EXPIRED_CERTIFICATES}
 * and
 * {@link DatabaseMaintenanceWorkerConstants#PROP_DELETE_REVOKED_CERTIFICATES}
 * booleans. Going forward the radio constant is the source of truth and
 * the legacy booleans are read-only for migration purposes.
 *
 * <p>The CRL-side cleanup
 * ({@link DatabaseMaintenanceWorkerConstants#PROP_DELETE_EXPIRED_CRLS}) is
 * a separate sweep over {@code CRLData} — independent of the cert-side
 * radio (it operates on a different table) and runs whenever its
 * checkbox is ticked regardless of which cert-deletion mode is selected,
 * including {@code MODE_NONE}. It uses the same {@code delayAfterExpiration}
 * value as {@code MODE_EXPIRED}. All deletions run in separate
 * transactions to avoid long table locks.
 */
public class DatabaseMaintenanceWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(DatabaseMaintenanceWorker.class);

    /** Cap on the number of expired CRLs purged per worker invocation, per issuer. */
    private static final int CRL_PURGE_PER_ISSUER_CAP = 10_000;

    @Override
    public void canWorkerRun(final Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // No prerequisites — the database is always available; the worker is
        // a no-op when no match criteria are enabled. Validation of the
        // numeric/enumeration properties happens in work() so the operator
        // sees the failure in the service-run log rather than at config time.
    }

    @Override
    public ServiceExecutionResult work(final Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // Normalize property names: the admin-gui form sets worker-specific
        // properties without a prefix (e.g. 'certDeletionMode=REVOKED'), but
        // the `ejbca.sh service create/edit` CLI only accepts properties
        // whose names start with 'worker.' for a brand-new service. Copy
        // any worker.X=v entries to a bare X=v key so this worker can be
        // configured equally from either path.
        normaliseWorkerPropertyPrefixes();

        final String certMode = resolveCertDeletionMode();
        final boolean matchExpiredCrls = readBoolean(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CRLS);

        if (DatabaseMaintenanceWorkerConstants.MODE_NONE.equals(certMode) && !matchExpiredCrls) {
            return new ServiceExecutionResult(Result.NO_ACTION,
                    "Database Maintenance Worker: cert deletion mode is NONE and CRL deletion disabled.");
        }

        final int batchSize = readBatchSize();

        final CertificateStoreSessionLocal certStore =
                (CertificateStoreSessionLocal) ejbs.get(CertificateStoreSessionLocal.class);
        final CrlStoreSessionLocal crlStore =
                (CrlStoreSessionLocal) ejbs.get(CrlStoreSessionLocal.class);
        final CaSessionLocal caSession =
                (CaSessionLocal) ejbs.get(CaSessionLocal.class);

        int certDeletedCount = 0;
        int expiredCrlCount = 0;
        final List<String> failures = new ArrayList<>();

        // Cert-side: dispatch on the radio mode.
        // MODE_EXPIRED — catches E + R (everything past notAfter regardless of revocation).
        // MODE_REVOKED — catches r + R (everything revoked-by-reason regardless of expiry).
        // MODE_NONE    — skip cert deletion entirely.
        try {
            if (DatabaseMaintenanceWorkerConstants.MODE_EXPIRED.equals(certMode)) {
                final Date expiredBefore = computeExpiredBefore();
                final Set<String> deleted = certStore.deleteCertificatesMatchingInSeparateTransactions(
                        /* issuerDns = */ null, expiredBefore, /* revokedBefore = */ null,
                        /* revocationReasons = */ null, batchSize, admin, new HashSet<>());
                certDeletedCount = deleted.size();
                if (log.isDebugEnabled()) {
                    log.debug("Deleted " + certDeletedCount + " cert row(s) — MODE_EXPIRED, expiredBefore=" + expiredBefore);
                }
            } else if (DatabaseMaintenanceWorkerConstants.MODE_REVOKED.equals(certMode)) {
                final Date revokedBefore = computeRevokedBefore();
                final Set<RevocationReasons> reasons = parseRevocationReasons();
                if (reasons.isEmpty()) {
                    failures.add("MODE_REVOKED: no valid revocation reasons configured (property '"
                            + DatabaseMaintenanceWorkerConstants.PROP_REVOCATION_REASONS + "').");
                } else {
                    final Set<String> deleted = certStore.deleteCertificatesMatchingInSeparateTransactions(
                            /* issuerDns = */ null, /* expiredBefore = */ null, revokedBefore, reasons,
                            batchSize, admin, new HashSet<>());
                    certDeletedCount = deleted.size();
                    if (log.isDebugEnabled()) {
                        log.debug("Deleted " + certDeletedCount + " cert row(s) — MODE_REVOKED, revokedBefore="
                                + revokedBefore + ", reasons=" + reasons);
                    }
                }
            }
            // MODE_NONE: no-op for cert deletion.
        } catch (ServiceExecutionFailedException e) {
            failures.add("Certificate deletion (" + certMode + "): " + e.getMessage());
        } catch (RuntimeException e) {
            log.error("Database Maintenance Worker: error during certificate sweep (" + certMode + ").", e);
            failures.add("Certificate deletion (" + certMode + "): " + e.getMessage());
        }

        // CRL-side: independent of cert deletion mode.
        if (matchExpiredCrls) {
            try {
                final Date expiredBefore = computeExpiredBefore();
                expiredCrlCount = purgeExpiredCrls(crlStore, caSession, expiredBefore);
                if (log.isDebugEnabled()) {
                    log.debug("Deleted " + expiredCrlCount + " expired CRL row(s) older than " + expiredBefore);
                }
            } catch (ServiceExecutionFailedException e) {
                failures.add("Match expired CRLs: " + e.getMessage());
            } catch (RuntimeException e) {
                log.error("Database Maintenance Worker: error deleting expired CRLs.", e);
                failures.add("Match expired CRLs: " + e.getMessage());
            }
        }

        return summarise(certDeletedCount, expiredCrlCount, failures);
    }

    /**
     * Read the cert-deletion mode from properties, falling back to the legacy
     * boolean flags (deleteExpiredCertificates / deleteRevokedCertificates)
     * when PROP_CERT_DELETION_MODE is absent — for backward compatibility
     * with pre-radio worker configurations that used the dual-flag form.
     */
    private String resolveCertDeletionMode() {
        final String explicit = properties.getProperty(
                DatabaseMaintenanceWorkerConstants.PROP_CERT_DELETION_MODE);
        if (explicit != null && !explicit.trim().isEmpty()) {
            return explicit.trim();
        }
        // Legacy fallback — derive from old booleans.
        if (readBoolean(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CERTIFICATES)) {
            return DatabaseMaintenanceWorkerConstants.MODE_EXPIRED;
        }
        if (readBoolean(DatabaseMaintenanceWorkerConstants.PROP_DELETE_REVOKED_CERTIFICATES)) {
            return DatabaseMaintenanceWorkerConstants.MODE_REVOKED;
        }
        return DatabaseMaintenanceWorkerConstants.MODE_NONE;
    }

    /* ---------- helpers ---------- */

    /**
     * Copies any {@code worker.X=v} entry to a bare {@code X=v} key when the
     * unprefixed form isn't already present. The unprefixed form is what the
     * admin-gui form and the worker code itself use; the prefixed form is
     * the only way {@code ejbca.sh service create} will accept a previously
     * unknown property at the CLI. This lets the worker be configured
     * equally from either path.
     */
    private void normaliseWorkerPropertyPrefixes() {
        final String prefix = "worker.";
        for (final String key : new java.util.ArrayList<>(properties.stringPropertyNames())) {
            if (key.startsWith(prefix)) {
                final String unprefixed = key.substring(prefix.length());
                if (!properties.containsKey(unprefixed)) {
                    properties.setProperty(unprefixed, properties.getProperty(key));
                }
            }
        }
    }

    /**
     * Returns {@code now − delayAfterExpiration} for the expired criterion
     * and the CRL cleanup. Uses {@link BaseWorker#getTimeBeforeExpire(String, String)}
     * which throws on a 0-value — that's correct here because the expired
     * criterion is meant to operate on a non-zero quarantine window.
     */
    private Date computeExpiredBefore() throws ServiceExecutionFailedException {
        final long delayMillis = getTimeBeforeExpire(
                DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEUNIT,
                DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEVALUE);
        return new Date(System.currentTimeMillis() - delayMillis);
    }

    /**
     * Returns {@code now − delayAfterRevocation} for the revoked criterion.
     * Inlined (rather than calling {@link BaseWorker#getTimeBeforeExpire(String, String)})
     * because that helper caches its first result on the worker instance,
     * which would conflict with the separate call for the expired criterion.
     *
     * <p>0 is a valid choice here (no quarantine — reap on the next tick),
     * unlike the expired branch where 0 is rejected by BaseWorker.
     */
    private Date computeRevokedBefore() throws ServiceExecutionFailedException {
        final String unit = properties.getProperty(
                DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEUNIT,
                DatabaseMaintenanceWorkerConstants.DEFAULT_REVOKE_DELAY_TIMEUNIT);
        final String value = properties.getProperty(
                DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEVALUE,
                String.valueOf(DatabaseMaintenanceWorkerConstants.DEFAULT_REVOKE_DELAY_TIMEVALUE));
        final int intValue;
        try {
            intValue = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new ServiceExecutionFailedException(
                    "Database Maintenance Worker: revoke-delay value '" + value + "' is not a number");
        }
        if (intValue < 0) {
            throw new ServiceExecutionFailedException(
                    "Database Maintenance Worker: revoke-delay value must be non-negative (got " + intValue + ")");
        }
        final int seconds = timeUnitToSeconds(unit);
        return new Date(System.currentTimeMillis() - (long) intValue * seconds * 1000L);
    }

    /** Reads a boolean property, defaulting to {@code false} if missing or malformed. */
    private boolean readBoolean(final String key) {
        return Boolean.parseBoolean(properties.getProperty(key));
    }

    /** Reads the batch-size property, falling back to {@link DatabaseMaintenanceWorkerConstants#DEFAULT_BATCH_SIZE}. */
    private int readBatchSize() {
        final String raw = properties.getProperty(DatabaseMaintenanceWorkerConstants.PROP_BATCH_SIZE);
        if (StringUtils.isBlank(raw)) {
            return DatabaseMaintenanceWorkerConstants.DEFAULT_BATCH_SIZE;
        }
        try {
            final int value = Integer.parseInt(raw.trim());
            return value > 0 ? value : DatabaseMaintenanceWorkerConstants.DEFAULT_BATCH_SIZE;
        } catch (NumberFormatException e) {
            log.warn("Database Maintenance Worker: '" + DatabaseMaintenanceWorkerConstants.PROP_BATCH_SIZE
                    + "' is not a number (got '" + raw + "'); using default "
                    + DatabaseMaintenanceWorkerConstants.DEFAULT_BATCH_SIZE);
            return DatabaseMaintenanceWorkerConstants.DEFAULT_BATCH_SIZE;
        }
    }

    /**
     * Parses {@link DatabaseMaintenanceWorkerConstants#PROP_REVOCATION_REASONS}
     * into a {@link Set} of {@link RevocationReasons}. Tokens that do not
     * match a known enum name are logged at WARN and dropped.
     */
    private Set<RevocationReasons> parseRevocationReasons() {
        final String raw = properties.getProperty(
                DatabaseMaintenanceWorkerConstants.PROP_REVOCATION_REASONS,
                DatabaseMaintenanceWorkerConstants.DEFAULT_REVOCATION_REASONS);
        final Set<RevocationReasons> result = EnumSet.noneOf(RevocationReasons.class);
        for (final String token : raw.split(",")) {
            final String trimmed = token.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            try {
                result.add(RevocationReasons.valueOf(trimmed));
            } catch (IllegalArgumentException e) {
                log.warn("Database Maintenance Worker: unknown revocation reason '" + trimmed
                        + "' in property '" + DatabaseMaintenanceWorkerConstants.PROP_REVOCATION_REASONS
                        + "'; ignoring.");
            }
        }
        return result;
    }

    /**
     * Iterates every CA in the system, queries for expired CRLs whose
     * {@code nextUpdate} is older than {@code maximumDate}, and deletes each
     * one — keeping the most recent base and delta CRL for the issuer (the
     * underlying query excludes the latest CRL numbers).
     *
     * @return total number of CRLs deleted across all issuers.
     */
    private int purgeExpiredCrls(final CrlStoreSessionLocal crlStore, final CaSessionLocal caSession,
            final Date maximumDate) {
        int totalDeleted = 0;
        final List<Integer> caIds = caSession.getAllCaIds();
        for (final Integer caId : caIds) {
            final CAInfo caInfo = caSession.getCAInfoInternal(caId);
            if (caInfo == null) {
                continue;
            }
            final String issuerDn = caInfo.getSubjectDN();
            if (StringUtils.isBlank(issuerDn)) {
                continue;
            }
            final int lastBaseCrlNumber = crlStore.getLastCRLNumber(issuerDn, 0, /* deltaCRL = */ false);
            final int lastDeltaCrlNumber = crlStore.getLastCRLNumber(issuerDn, 0, /* deltaCRL = */ true);
            final List<CrlMetadataHolderDto> expired = crlStore.findExpiredCrlByIssuerDn(
                    issuerDn, maximumDate.getTime(), lastBaseCrlNumber, lastDeltaCrlNumber,
                    CRL_PURGE_PER_ISSUER_CAP);
            for (final CrlMetadataHolderDto holder : expired) {
                crlStore.delete(holder, admin);
                totalDeleted++;
            }
            if (log.isDebugEnabled() && !expired.isEmpty()) {
                log.debug("Deleted " + expired.size() + " expired CRL(s) for issuer '" + issuerDn + "'.");
            }
        }
        return totalDeleted;
    }

    private ServiceExecutionResult summarise(final int certDeletedCount, final int expiredCrls,
            final List<String> failures) {
        final String summary = "Database Maintenance Worker: deleted " + certDeletedCount
                + " certificate(s) matching criteria, " + expiredCrls + " expired CRL(s).";
        if (!failures.isEmpty()) {
            return new ServiceExecutionResult(Result.FAILURE,
                    summary + " Errors: " + constructNameList(failures));
        }
        if (certDeletedCount == 0 && expiredCrls == 0) {
            return new ServiceExecutionResult(Result.NO_ACTION,
                    "Database Maintenance Worker: nothing matched the configured filters.");
        }
        return new ServiceExecutionResult(Result.SUCCESS, summary);
    }
}
