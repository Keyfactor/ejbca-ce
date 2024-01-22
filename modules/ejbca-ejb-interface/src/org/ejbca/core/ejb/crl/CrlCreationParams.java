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
package org.ejbca.core.ejb.crl;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Additional parameters for CRL creation
 */
public class CrlCreationParams implements Serializable {

    private static final long serialVersionUID = 1L;

    /** Always archive expired certificates for at least 10 seconds */
    public static final long MINIMUM_ARCHIVAL_MILLISECS = 10_000;

    private Date validFrom;
    private final long archivalDeadline;

    /** Uses the current date and uses NO archival time limit */
    public CrlCreationParams() {
        this(new Date());
    }

    public CrlCreationParams(final Date validFrom) {
        this(validFrom, Long.MAX_VALUE);
    }

    private CrlCreationParams(final Date validFrom, final long archivalDeadline) {
        this.validFrom = validFrom != null ? validFrom : new Date();
        this.archivalDeadline = archivalDeadline;
    }

    public CrlCreationParams(final long archivalTimeLimit, final TimeUnit archivalLimitTimeUnit) {
        this(new Date(), archivalTimeLimit, archivalLimitTimeUnit);
    }

    public CrlCreationParams(final Date validFrom, final long archivalTimeLimit, final TimeUnit archivalLimitTimeUnit) {
        this(validFrom, System.currentTimeMillis() + archivalLimitTimeUnit.toMillis(archivalTimeLimit));
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(final Date validFrom) {
        this.validFrom = validFrom;
    }

    public long getArchivalDeadline() {
        return archivalDeadline;
    }

}
