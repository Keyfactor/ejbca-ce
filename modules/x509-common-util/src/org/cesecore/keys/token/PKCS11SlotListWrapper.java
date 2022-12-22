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
package org.cesecore.keys.token;

/**
 * Interface for classes that wraps C_GetSlotList calls to P11 to get information about slots/tokens and their labels
 * This interface is used through the UI both when using SunP11 and P11NG, to display slot labels.
 */
public interface PKCS11SlotListWrapper {
    /**
     * Get a (cached) list of p11 slot IDs to slots that has a token.
     * @return (cached) list of slot IDs.
     */
    public long[] getSlotList();

    /**
     * Get the token label of a specific slot ID.
     * @param slotID the ID of the slot
     * @return the token label, or null if no matching token was found.
     */
    public char[] getTokenLabel(long slotID);    
}
