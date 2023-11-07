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

package org.ejbca.ui.web;

import org.apache.commons.lang3.RandomStringUtils;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.InternalConfiguration;

/**
 * Helper class used to add a version string to static web resources.
 */
public class StaticResourceVersioning {

    private static final int RANDOM_PART_LENGTH = 5;
    public static final String VERSION;

    private StaticResourceVersioning() {
        throw new IllegalStateException("Utility class");
    }

    static {
        String versionString = InternalConfiguration.getAppVersionNumber();
        // add a random string in non-production mode to avoid caching issues during development
        if (!EjbcaConfiguration.getIsInProductionMode()) {
            versionString += "-" + RandomStringUtils.randomAlphanumeric(RANDOM_PART_LENGTH);
        }
        VERSION = sanitize(versionString);
    }

    /**
     * Sanitizes the version string by removing any unwanted characters that could brake URLs.
     * @param input the version string to sanitize
     * @return a lowercase string containing only a-z, 0-9, "-" and "." characters
     */
    private static String sanitize(String input) {
        return input.toLowerCase().replaceAll("[^a-z0-9\\-.]", "");
    }
}
