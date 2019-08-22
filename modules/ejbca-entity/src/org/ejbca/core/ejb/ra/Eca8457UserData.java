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

package org.ejbca.core.ejb.ra;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectionStringBuilder;

/**
 * Due to a mistake in EJBCA 7.2.0, the behavior* of getProtectString method was changed, leading to a backwards
 * incompatibility. The old behavior was restored 7.2.1.1, so upgrades from 7.1.x and older will work. Since
 * reverting is also not backwards compatible (protect strings must be identical), we need special handling
 * to support data signed/hashed in 7.2.0 and 7.2.1. This is what this class does.
 * <p>
 * * The behavior change was that hardTokenIssuerId was removed from the getProtectString method. It was
 * added back again in 7.2.1.1, and this class handles the behavior of 7.2.0 and 7.2.1 where hardTokenIssuerId
 * was absent. hardTokenIssuerId is a deprecated field that is no longer used, so there are no security
 * implications of the changes. The signing/HMAC'ing is not affected at all; the presence of a valid
 * signature/HMAC has always been required.
 * 
 * @version $Id$
 */
public class Eca8457UserData extends UserData {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(Eca8457UserData.class);

    public Eca8457UserData(final UserData data) {
        super(data);
    }

    @Override
    protected String getProtectString(final int version) {
        if (log.isDebugEnabled()) {
            log.debug("Verification of row protected data for End Entity " + getUsername()
                    + " failed. Trying to fix the protect string now.");
        }
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        // rowVersion is automatically updated by JPA, so it's not important, it is only used for optimistic locking
        build.append(getUsername());
        if (version>=2) {
            // From version 2 we always use empty String here to allow future migration between databases when this value is unset
            build.append(getSubjectDnNeverNull());
        } else {
            build.append(getSubjectDN());
        }
        build.append(getCardNumber()).append(getCaId());
        if (version>=2) {
            // From version 2 we always use empty String here to allow future migration between databases when this value is unset
            build.append(getSubjectAltNameNeverNull());
        } else {
            build.append(getSubjectAltName());
        }
        build.append(getCardNumber());
        // Note: no .append(getHardTokenIssuerId) here
        build.append(getSubjectEmail()).append(getStatus()).append(getType()).append(getClearPassword()).append(getPasswordHash()).append(getTimeCreated()).append(getTimeModified());
        build.append(getEndEntityProfileId()).append(getCertificateProfileId()).append(getTokenType()).append(getExtendedInformationData());
        return build.toString();
    }
}