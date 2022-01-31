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

package org.cesecore.legacy;

import org.apache.log4j.Logger;
import org.cesecore.dbprotection.ProtectionStringBuilder;
import org.cesecore.roles.member.RoleMemberData;

/**
 * RoleMemberData was updated in 7.5.0 with a new field. The getProtectString method was updated with that field,
 * however the getProtectVersion method wasn't updated. Thus upgrading would fail from versions <7.5 to newer ones
 * if database protection was switched on.
 * <p>
 * The aim of Eca10289RoleMemberData is to fix this problem. Eca10289RoleMemberData behaves exactly
 * like RoleMemberData, but replaces any faulty substrings found in the protect string returned by
 * getProtectString() before returning it to the caller.
 * <p>
 * This class, the regression test and all references to these can be safely removed when we are sure that all
 * installations have performed a post-upgrade on EJBCA version 8.x or later.
 */
@SuppressWarnings("serial")
@Deprecated
public class Eca10289RoleMemberData extends RoleMemberData {
    private final static Logger log = Logger.getLogger(Eca10289RoleMemberData.class);

    public Eca10289RoleMemberData(final RoleMemberData data) {
        // We cannot use the standard constructor, since it performs upgrades,
        // which could modify the data and change the resulting protect string.
        super();
        setPrimaryKey(data.getPrimaryKey());
        setTokenType(data.getTokenType());
        setTokenIssuerId(data.getTokenIssuerId());
        setTokenProviderId(data.getTokenProviderId());
        setTokenMatchKey(data.getTokenMatchKey());
        setTokenMatchOperator(data.getTokenMatchOperator());
        setTokenMatchValue(data.getTokenMatchValue());
        setRoleId(data.getRoleId());
        setDescription(data.getDescription());
        this.setRowVersion(data.getRowVersion());
        this.setRowProtection(data.getRowProtection());
    }

    @Override
    protected String getProtectString(final int rowversion) {
        if (log.isDebugEnabled()) {
            log.debug("Verification of row protected data for Role Member with role id " + getRoleId()
                    + " and description '" + getDescription() + "'"
                    + " failed. Trying to fix the protect string now.");
        }
        if (log.isTraceEnabled()) {
            log.trace("protectString before replacement: " + super.getProtectString(rowversion));
        }
        final ProtectionStringBuilder build = new ProtectionStringBuilder();
        build.append(getPrimaryKey()).append(getTokenType()).append(getTokenIssuerId()).append(getTokenProviderId()).
                append(getTokenMatchKey()).append(getTokenMatchOperator()).
                append(getTokenMatchValue()).append(getRoleId()).append(getDescription());
        return build.toString();
    }
}