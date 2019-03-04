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
package org.ejbca.core.model.validation.domainblacklist;

import java.util.Map;

/**
 * Splits the domain into pieces by "." and checks if any piece is present in the blacklist
 *
 * @version $Id$
 */
public class DomainBlacklistComponentChecker implements DomainBlacklistChecker {


    private Map<String,String> blacklist;

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_CHECK_COMPONENT";
    }


    @Override
    public void initialize(final Map<Object, Object> configData, final Map<String,String> blacklist) {
        this.blacklist = blacklist;
    }

    @Override
    public String check(final String domain) {
        if (blacklist == null) {
            throw new IllegalStateException("Blacklist not configured!");
        }
        final String[] domainParts = domain.split("\\.");
        for (final String domainPart : domainParts) {
            final String blacklistedDomain = blacklist.get(domainPart);
            if (blacklistedDomain != null) {
                return blacklistedDomain; // Blacklisted
            }
        }
        return null; // Not blacklisted
    }
}
