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
import java.util.Set;

import org.cesecore.util.NameTranslatable;

/**
 * Domain Blacklist Checkers check domain names against a blacklist.
 * Each object corresponds to a combination of one blacklist and one type of check.
 * Domain Blacklist Checkers are intended to be cached (in a DomainBlacklistValidator) and re-used.
 * 
 * @version $Id$
 */
public interface DomainBlacklistChecker extends NameTranslatable {

    /**
     * Initializes this blacklist checker with a given blacklist.
     * @param configData Data hash map with configuration options (if the checker is configurable)
     * @param blacklist Set of all domains or domain components to blacklist. May not be modified after initialization.
     */
    void initialize(final Map<Object,Object> configData, final Set<String> blacklist);

    /**
     * Checks a domain name against this blacklist. Must be thread safe.
     * @param domain Domain to check
     * @return Return false if blocked by blacklist.
     */
    boolean check(final String domain);

    // TODO configurable checkers (ECA-6052). might not be needed for 7.0.1
}
