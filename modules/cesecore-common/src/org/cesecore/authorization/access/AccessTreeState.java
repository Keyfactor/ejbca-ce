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

package org.cesecore.authorization.access;

/**
 * Enum adapted from the constants in AccessTreeNode in EJBCA. Represents the state of an accessTree node.
 * 
 * @version $Id$
 * 
 */

public enum AccessTreeState {
    STATE_UNKNOWN(1), STATE_ACCEPT(2), STATE_ACCEPT_RECURSIVE(3), STATE_DECLINE(4);

    private AccessTreeState(int legacyNumber) {
        this.legacyNumber = legacyNumber;
    }

    public int getLegacyNumber() {
        return legacyNumber;
    }

    private int legacyNumber;
}
