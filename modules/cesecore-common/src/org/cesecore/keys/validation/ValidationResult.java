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

package org.cesecore.keys.validation;

import java.io.Serializable;

/**
 * Contains the result of a validation performed by a validator executed
 * during the "Approval" phase.
 *
 * <p><b>Implementation note:</b> This object is serialised as a part of
 * ApprovalRequest objects in EJBCA. Care should be taken when making
 * changes to ensure backwards compatibility.
 *
 * @version $Id$
 */
public class ValidationResult implements Serializable {
    private static final long serialVersionUID = 1L;
    private final String message;
    private final boolean success;

    /***
     * Create a new validation result.
     *
     * @param message the message produced by the validator.
     * @param success true if validation succeeded, false otherwise.
     */
    public ValidationResult(final String message, final boolean success) {
        this.message = message;
        this.success = success;
    }

    /**
     * Get a message produced by the validator.
     *
     * @return the validation message.
     */
    public String getMessage() {
        return message;
    }

    /**
     * Get a boolean indicating whether the validation was successful or not.
     *
     * @return the validation status, as a boolean.
     */
    public boolean isSuccessful() {
        return success;
    }

    @Override
    public String toString() {
        return String.format("(%s, %s)", success, message);
    }
}
