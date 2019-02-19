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
 * TODO ECA-6052
 *
 * @version $Id$
 */
public class DomainBlacklistAsciiLookalikeNormalizer implements DomainBlacklistNormalizer {

    @Override
    public String getNameKey() {
        return "DOMAINBLACKLISTVALIDATOR_NORMALIZATION_ASCIILOOKALIKE";
    }

    @Override
    public void initialize(final Map<Object, Object> configData) {
        // TODO ECA-6052

    }

    @Override
    public String normalize(final String domain) {
        // TODO ECA-6052
        return null;
    }

}
