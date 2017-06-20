/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.validation;

import java.util.Properties;

/**
 * All Custom key validators must implement this interface.
 * 
 * @version $Id: ICustomKeyValidator.java 22117 2017-03-01 12:12:00Z anjakobs $
 */

public interface ICustomKeyValidator extends IKeyValidator {

    /**
     * Gets the class path of the custom key validator.
     * @return the class path.
     */
    String getClasspath();

    /**
     *  Method called to all newly created ICustomKeyValidator to set it up with
     *  saved configuration.
     */

    /**
     * Initializes the key validator.
     */
    void init();

    /**
     * Read only.
     * @return true if this key validator type shouldn't be editable.
     */
    boolean isReadOnly();
}
