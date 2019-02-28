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

import org.apache.commons.lang.StringUtils;

import java.util.Map;
import java.util.Set;

/**
 * Removes subdomain one by one, and checks if subdomain is present in the blacklist
 *
 * @version $Id$
 */
public class DomainBlacklistTopDomainChecker implements DomainBlacklistChecker {
    private Set<String> blacklist;

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_CHECK_TOPDOMAIN";
    }

    @Override
    public void initialize(Map<Object, Object> configData, Set<String> blacklist) {
        this.blacklist = blacklist;
    }

    @Override
    public boolean check(String domain) {
        if (blacklist == null) {
            throw new IllegalStateException("Blacklist not configured!");
        }
        String checkingString = domain;
        while (StringUtils.isNotEmpty(checkingString)) {
            for (String blackListedDomain : blacklist) {
                if (blackListedDomain.equals(checkingString)) {
                    return false;
                }
            }
            int indexOfPoint = checkingString.indexOf(".");
            if (indexOfPoint > 0) {
                checkingString = checkingString.substring(indexOfPoint + 1);
            } else {
                checkingString = null;
            }
        }
        return true;
    }
}
