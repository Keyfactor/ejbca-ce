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

import org.apache.commons.lang.StringUtils;

/**
 * Removes subdomain one by one, and checks if subdomain is present in the blacklist
 *
 * @version $Id$
 */
public class DomainBlacklistBaseDomainChecker implements DomainBlacklistChecker {
    private Map<String,String> blacklist;

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_CHECK_BASEDOMAIN";
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
        String checkingString = domain;
        while (StringUtils.isNotEmpty(checkingString)) {
            final String blacklistedDomain = blacklist.get(checkingString);
            if (blacklistedDomain != null) {
                return blacklistedDomain; // Blacklisted
            }
            int indexOfPoint = checkingString.indexOf(".");
            if (indexOfPoint > 0) {
                checkingString = checkingString.substring(indexOfPoint + 1);
            } else {
                break; // No more subdomains
            }
        }
        return null; // Not blacklisted
    }
}
