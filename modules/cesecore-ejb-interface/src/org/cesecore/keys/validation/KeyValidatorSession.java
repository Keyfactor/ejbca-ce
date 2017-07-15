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

/**
 * Interface for key validator operations.
 *
 * @version $Id$
 */
public interface KeyValidatorSession {
    
    /**
     * Flushes the key validators cache to ensure that next time they are read from database.
     */
    void flushKeyValidatorCache();
}
