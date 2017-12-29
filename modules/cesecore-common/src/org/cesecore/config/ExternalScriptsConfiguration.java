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
package org.cesecore.config;

/**
 * Type for configurable calls to external scripts.
 *
 * @version $Id$
 */
public interface ExternalScriptsConfiguration {

	/**
	 * Sets if external scripts on the local are allowed to be called.
	 * @param value the value.
	 */
    void setEnableExternalScripts(boolean value);

    /**
     * Gets if external scripts on the local are allowed to be called.
     * @return the value.
     */
    boolean getEnableExternalScripts();

    /**
     * Get a string containing a whitelist of external scripts permitted to be executed by "External Command Validators"
     * @return the contents of the External Scripts whitelist
     */
    String getExternalScriptsWhitelist();

    /**
     * Sets an external scripts whitelist.
     * @see #getExternalScriptsWhitelist()
     * @param value a multi-line string containing the contents of the whitelist
     */
    void setExternalScriptsWhitelist(final String value);

    /**
     * Gets a value indicating whether a whitelist for external commands should be used.
     * @return true if the the whitelist retrieved from {@link #getExternalScriptsWhitelist()} should be used
     * */
    boolean getIsExternalScriptsWhitelistEnabled();

    /**
     * Sets a value indicating whether a whitelist for external commands should be used.
     * @see #getEnableExternalScripts()
     * @param value true if a whitelist should be used, false otherwise
     */
    void setIsExternalScriptsWhitelistEnabled(final boolean value);
}
