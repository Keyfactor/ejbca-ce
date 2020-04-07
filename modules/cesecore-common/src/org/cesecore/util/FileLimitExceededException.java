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

package org.cesecore.util;

import java.io.IOException;

/**
 * Thrown when there are too many files.
 * 
 * @version $Id$
 */
public class FileLimitExceededException extends IOException {
    public FileLimitExceededException(final String message) {
        super(message);
    }
}
