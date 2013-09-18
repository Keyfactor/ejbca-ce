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
import org.cesecore.keybind.impl.OcspKeyBinding;

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

    public boolean isNonExistingGood(StringBuffer url, OcspKeyBinding ocspKeyBinding) {
        // First we read the global default
        boolean nonExistingIsGood = this.nonExistingIsGood;
        // If we have an OcspKeyBinding for this request we use it to override the default
        if (ocspKeyBinding != null) {
            nonExistingIsGood = ocspKeyBinding.getNonExistingGood();
        }
        // Finally, if we have explicit configuration of the URL, this will potentially override the value once again
        if (nonExistingIsGood) {
            return !isRegexFulFilled(url, nonExistingIsBadOverideRegex);
        }
        return isRegexFulFilled(url, nonExistingIsGoodOverideRegex);
    }

    private boolean isRegexFulFilled(StringBuffer target, Pattern pattern) {
        if (pattern == null || target == null) {
            return false;
        }
        return pattern.matcher(target.toString()).matches();
    }
}
