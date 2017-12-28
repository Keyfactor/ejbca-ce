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
public interface EnableExternalScriptsConfiguration {

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
}
