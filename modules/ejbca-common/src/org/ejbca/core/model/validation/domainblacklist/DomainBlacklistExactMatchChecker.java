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
package org.ejbca.core.model.validation.domainblacklist;

import java.util.Map;

/**
 * Performs an exact string match against a blacklist.
 *
 * @version $Id$
 */
public class DomainBlacklistExactMatchChecker implements DomainBlacklistChecker {

    private Map<String,String> blacklist;

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_CHECK_EXACTMATCH";
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
        return blacklist.get(domain); // Returns null if not blacklisted
    }

}
