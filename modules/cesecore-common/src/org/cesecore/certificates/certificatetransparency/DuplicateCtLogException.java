/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
