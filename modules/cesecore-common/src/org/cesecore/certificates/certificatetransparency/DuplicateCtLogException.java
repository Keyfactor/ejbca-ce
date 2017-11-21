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

package org.cesecore.certificates.certificatetransparency;

/**
 * Exception which occurs whenever a user tries to add a CT log which already exists within
 * the given scope.
 * @version $Id$
 */
public class DuplicateCtLogException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public DuplicateCtLogException(final String message) {
        super(message);
    }
}
