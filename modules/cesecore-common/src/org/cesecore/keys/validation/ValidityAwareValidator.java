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

import java.util.Date;

import org.cesecore.profiles.Profile;

public interface ValidityAwareValidator extends Profile {

    /**
     * Sets the notBefore field.
     * @param date the validity date.
     */
    void setNotBefore(Date date);

    /**
     * Sets the notBefore field.
     * @param formattedDate the formatted validity date string.
     */
    void setNotBeforeAsString(String formattedDate);

    /**
     * Gets the notBefore field.
     * @return the validity not before field.
     */
    Date getNotBefore();

    /**
     * Gets the notBefore field.
     * @return the validity not before field as string.
     */
    String getNotBeforeAsString();

    /**
     * Gets the notBefore condition index (see {@link KeyValidatorDateConditions}).
     * @return the index of the condition type.
     */
    int getNotBeforeCondition();

    /**
     * Sets the notBefore condition index (see {@link KeyValidatorDateConditions}).
     * @param index the index of the condition type.
     */
    void setNotBeforeCondition(int index);

    /**
     * Sets the notAfter field.
     * @param date the validity date.
     */
    void setNotAfter(Date date);

    /**
     * Sets the notAfter field.
     * @param formattedDate the formatted validity date string.
     */
    void setNotAfterAsString(String formattedDate);

    /**
     * Gets the notAfter field.
     * @return the validity not after field.
     */
    Date getNotAfter();

    /**
     * Gets the notAfter field.
     * @return the validity not after field as string.
     */
    String getNotAfterAsString();

    /**
     * Gets the notAfter field.
     * @return the validity not after field as string.
     */
    int getNotAfterCondition();

    /**
     * Sets the notAfter condition index (see {@link KeyValidatorDateConditions}).
     * @param index the index of the condition type.
     */
    void setNotAfterCondition(int index);
}
