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
package org.cesecore.keys.token.p11;

/**
 * All users of the {@link P11Slot} slot must implement this interface. The user may decide whether deactivation is allowed or not. Deactivation of a
 * user is done when the {@link P11Slot} object wants to reset P11 session (disconnect and reconnect).
 * <p>
 * If deactivation is allowed and {@link #deactivate()} called the user should:<br>
 * Deactivate itself (answer false to {@link #isActive()}) and call {@link P11Slot#logoutFromSlotIfNoTokensActive()} Then
 * {@link P11Slot#getProvider()} must be called before using the provider again.
 * </p>
 * <p>
 * If deactivation is not allowed then the user may just continue to answer true to {@link #isActive()}.
 * </p>  
 * 
 */
public interface P11SlotUser {
    /**
     * Called by the {@link P11Slot} when resetting the slot.
     * 
     * @throws Exception
     */
    void deactivate() throws Exception;

    /**
     * The user should return true if not accepting a slot reset.
     * 
     * @return true if the slot is being used.
     */
    boolean isActive();
}