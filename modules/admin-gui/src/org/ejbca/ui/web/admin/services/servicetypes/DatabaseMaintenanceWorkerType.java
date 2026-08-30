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
package org.ejbca.ui.web.admin.services.servicetypes;

import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.util.PropertyTools;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorkerConstants;

import jakarta.faces.model.SelectItem;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;

/**
 * Database maintenance worker.
 */
public class DatabaseMaintenanceWorkerType extends BaseWorkerType {

    private static final long serialVersionUID = 1L;

    public static final String NAME = "DATABASEMAINTENANCEWORKER";

    private static final String WORKER_SUB_PAGE = "databasemaintenanceworker.xhtml";

    private String certDeletionMode = DatabaseMaintenanceWorkerConstants.DEFAULT_CERT_DELETION_MODE;
    private String delayTimeUnit  = DatabaseMaintenanceWorkerConstants.DEFAULT_DELAY_TIMEUNIT;
    private int delayTimeValue = DatabaseMaintenanceWorkerConstants.DEFAULT_DELAY_TIMEVALUE;
    private String revokeDelayTimeUnit  = DatabaseMaintenanceWorkerConstants.DEFAULT_REVOKE_DELAY_TIMEUNIT;
    private int revokeDelayTimeValue = DatabaseMaintenanceWorkerConstants.DEFAULT_REVOKE_DELAY_TIMEVALUE;
    private boolean deleteExpiredCrls = true;
    private String revocationReasons = DatabaseMaintenanceWorkerConstants.DEFAULT_REVOCATION_REASONS;
    private int batchSize = DatabaseMaintenanceWorkerConstants.DEFAULT_BATCH_SIZE;

    public DatabaseMaintenanceWorkerType() {
        super(WORKER_SUB_PAGE, NAME, true, DatabaseMaintenanceWorkerConstants.WORKER_CLASS);
        // No action available for this worker
        deleteAllCompatibleActionTypes();
        addCompatibleActionTypeName(NoActionType.NAME);
        // Only periodical interval available for this worker
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
    }

    @Override
    public Properties getProperties(final ArrayList<String> errorMessages) throws IOException {
        Properties ret = super.getProperties(errorMessages);
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_CERT_DELETION_MODE, certDeletionMode);
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEUNIT, delayTimeUnit);
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEVALUE, Integer.toString(delayTimeValue));
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEUNIT, revokeDelayTimeUnit);
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEVALUE, Integer.toString(revokeDelayTimeValue));
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CRLS, Boolean.toString(deleteExpiredCrls));
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_REVOCATION_REASONS, revocationReasons != null ? revocationReasons : "");
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_BATCH_SIZE, Integer.toString(batchSize));
        // Sync the legacy boolean flags from the radio mode so older
        // worker code paths and downstream tools that read the booleans
        // see a consistent picture.
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CERTIFICATES,
                Boolean.toString(DatabaseMaintenanceWorkerConstants.MODE_EXPIRED.equals(certDeletionMode)));
        ret.setProperty(DatabaseMaintenanceWorkerConstants.PROP_DELETE_REVOKED_CERTIFICATES,
                Boolean.toString(DatabaseMaintenanceWorkerConstants.MODE_REVOKED.equals(certDeletionMode)));
        return ret;
    }

    @Override
    public void setProperties(final Properties properties) throws IOException {
        super.setProperties(properties);
        delayTimeValue = PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEVALUE, delayTimeValue);
        delayTimeUnit = properties.getProperty(DatabaseMaintenanceWorkerConstants.PROP_DELAY_TIMEUNIT, delayTimeUnit);
        revokeDelayTimeValue = PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEVALUE, revokeDelayTimeValue);
        revokeDelayTimeUnit = properties.getProperty(DatabaseMaintenanceWorkerConstants.PROP_REVOKE_DELAY_TIMEUNIT, revokeDelayTimeUnit);
        deleteExpiredCrls = PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CRLS, deleteExpiredCrls);
        revocationReasons = properties.getProperty(DatabaseMaintenanceWorkerConstants.PROP_REVOCATION_REASONS, revocationReasons);
        batchSize = PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_BATCH_SIZE, batchSize);
        // Resolve cert-deletion mode: explicit property wins; otherwise
        // derive from the legacy boolean flags for backward compatibility.
        final String explicitMode = properties.getProperty(DatabaseMaintenanceWorkerConstants.PROP_CERT_DELETION_MODE);
        if (explicitMode != null && !explicitMode.trim().isEmpty()) {
            certDeletionMode = explicitMode.trim();
        } else if (PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_DELETE_EXPIRED_CERTIFICATES, false)) {
            certDeletionMode = DatabaseMaintenanceWorkerConstants.MODE_EXPIRED;
        } else if (PropertyTools.get(properties, DatabaseMaintenanceWorkerConstants.PROP_DELETE_REVOKED_CERTIFICATES, false)) {
            certDeletionMode = DatabaseMaintenanceWorkerConstants.MODE_REVOKED;
        }
        // else: keep the existing default (MODE_NONE)
    }

    public String getCertDeletionMode() {
        return certDeletionMode;
    }

    public void setCertDeletionMode(final String certDeletionMode) {
        this.certDeletionMode = certDeletionMode;
    }

    /**
     * JSF accessor — the available radio-button options for cert deletion mode.
     */
    public List<SelectItem> getAvailableCertDeletionModes() {
        final List<SelectItem> items = new ArrayList<>();
        items.add(new SelectItem(DatabaseMaintenanceWorkerConstants.MODE_EXPIRED,
                "Delete expired certificates  (ELT: E + R)"));
        items.add(new SelectItem(DatabaseMaintenanceWorkerConstants.MODE_REVOKED,
                "Delete revoked certificates  (ELT: r + R)"));
        items.add(new SelectItem(DatabaseMaintenanceWorkerConstants.MODE_NONE,
                "None  (CRL deletions only)"));
        return items;
    }

    public String getDelayTimeUnit() {
        return delayTimeUnit;
    }

    public void setDelayTimeUnit(final String delayTimeUnit) {
        this.delayTimeUnit = delayTimeUnit;
    }

    public int getDelayTimeValue() {
        return delayTimeValue;
    }

    public void setDelayTimeValue(final int delayTimeValue) {
        this.delayTimeValue = delayTimeValue;
    }

    public String getRevokeDelayTimeUnit() {
        return revokeDelayTimeUnit;
    }

    public void setRevokeDelayTimeUnit(final String revokeDelayTimeUnit) {
        this.revokeDelayTimeUnit = revokeDelayTimeUnit;
    }

    public int getRevokeDelayTimeValue() {
        return revokeDelayTimeValue;
    }

    public void setRevokeDelayTimeValue(final int revokeDelayTimeValue) {
        this.revokeDelayTimeValue = revokeDelayTimeValue;
    }

    public boolean isDeleteExpiredCrls() {
        return deleteExpiredCrls;
    }

    public void setDeleteExpiredCrls(final boolean deleteExpiredCrls) {
        this.deleteExpiredCrls = deleteExpiredCrls;
    }

    public String getRevocationReasons() {
        return revocationReasons;
    }

    public void setRevocationReasons(final String revocationReasons) {
        this.revocationReasons = revocationReasons;
    }

    /**
     * JSF accessor — current selection for the multi-select listbox.
     *
     * <p>Backed by the same comma-separated {@link #revocationReasons} string
     * the worker reads, so values set via the GUI listbox and values set via
     * {@code ejbca.sh service edit worker.revocationReasons=SUPERSEDED,...}
     * round-trip through the same property without conversion.
     */
    public List<String> getSelectedRevocationReasons() {
        if (revocationReasons == null || revocationReasons.isEmpty()) {
            return Collections.emptyList();
        }
        return Arrays.asList(revocationReasons.split("\\s*,\\s*"));
    }

    public void setSelectedRevocationReasons(final List<String> selected) {
        if (selected == null || selected.isEmpty()) {
            this.revocationReasons = "";
        } else {
            // Preserve order, deduplicate.
            final LinkedHashSet<String> unique = new LinkedHashSet<>(selected);
            this.revocationReasons = String.join(",", unique);
        }
    }

    /**
     * JSF accessor — the available revocation reasons to show in the listbox.
     *
     * <p>Matches the curated {@code reasonableRevocationReasons} set already
     * defined in {@link RevocationReasons} (excludes NOT_REVOKED, both
     * CA-compromise variants, CERTIFICATE_HOLD, and REMOVE_FROM_CRL, which
     * aren't meaningful as "delete revoked certs" filter criteria for an
     * operator scheduling a cleanup job). Each {@link SelectItem} uses the
     * RFC 5280 string form (e.g. "SUPERSEDED") as the value and the
     * enum's {@code humanReadable} label as the display text.
     */
    public List<SelectItem> getAvailableRevocationReasons() {
        final List<SelectItem> items = new ArrayList<>();
        for (final RevocationReasons r : new RevocationReasons[] {
                RevocationReasons.UNSPECIFIED,
                RevocationReasons.KEYCOMPROMISE,
                RevocationReasons.AFFILIATIONCHANGED,
                RevocationReasons.SUPERSEDED,
                RevocationReasons.CESSATIONOFOPERATION,
                RevocationReasons.PRIVILEGESWITHDRAWN,
        }) {
            items.add(new SelectItem(r.getStringValue(), r.getHumanReadable()));
        }
        return items;
    }

    public int getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(final int batchSize) {
        this.batchSize = batchSize;
    }
}
