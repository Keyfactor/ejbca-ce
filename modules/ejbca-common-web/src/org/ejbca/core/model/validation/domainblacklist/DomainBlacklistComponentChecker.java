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
import java.util.Set;

/**
 * Splits the domain into peices by "." and checks if any piece is present in the blacklist
 * @version $Id$
 */
public class DomainBlacklistComponentChecker implements DomainBlacklistChecker {


    private Set<String> blacklist;

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_CHECK_COMPONENT";
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
        String[] domainParts = domain.split("\\.");

        for (int i = 0; i < domainParts.length; i++) {
            for (String blackListedDomain : blacklist) {
                if (blackListedDomain.equals(domainParts[i])) {
                    return false;
                }
            }
        }
        return true;
    }
}
