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
package org.cesecore.certificates.ocsp.cache;

import java.util.regex.Pattern;

import org.cesecore.config.OcspConfiguration;

/**
 * This cache contains non persistent configuration elements that need to be cached in order to be shared between all 
 * beans and servlets.
 * 
 * 
 * @version $Id$
 *
 */
public enum OcspConfigurationCache {
    INSTANCE;

    /* If true a certificate that does not exist in the database, but is issued by a CA the responder handles
     * will be treated as not revoked. Default (when value is true) is to treat is as "unknown".
     */
    private boolean nonExistingIsGood;
    /*
     * If this regex is fulfilled the "good" will be return even if {@link #nonExistingIsGood} is false;
     */
    private Pattern nonExistingIsGoodOverideRegex;
    /*
     * If this regex is fulfilled the "unknown" will be return even if {@link #nonExistingIsGood} is true;
     */
    private Pattern nonExistingIsBadOverideRegex;

    private OcspConfigurationCache() {
        reloadConfiguration();
    }

    public void reloadConfiguration() {
        nonExistingIsGood = OcspConfiguration.getNonExistingIsGood();
        {
            final String value = OcspConfiguration.getNonExistingIsGoodOverideRegex();
            nonExistingIsGoodOverideRegex = value != null ? Pattern.compile(value) : null;
        }
        {
            final String value = OcspConfiguration.getNonExistingIsBadOverideRegex();
            nonExistingIsBadOverideRegex = value != null ? Pattern.compile(value) : null;
        }
    }

    /**
     * @return the nonExistingIsGood
     */
    public boolean isNonExistingGood() {
        return nonExistingIsGood;
    }

    public boolean isNonExistingGood(StringBuffer url) {
        if (nonExistingIsGood) {
            return !isRegexFulFilled(url.toString(), nonExistingIsBadOverideRegex);
        }
        return isRegexFulFilled(url.toString(), nonExistingIsGoodOverideRegex);
    }

    private boolean isRegexFulFilled(String target, Pattern pattern) {
        if (pattern == null || target == null) {
            return false;
        }
        return pattern.matcher(target).matches();
    }
}
