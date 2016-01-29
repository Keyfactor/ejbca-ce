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
package org.ejbca.statedump.ejb;

/**
 * Represents a change of CA Subject DN (and CA Id also, which is computed from the Subject DN) 
 * @version $Id$
 */
public final class StatedumpCAIdChange {

    private final int fromId, toId;
    private final String toSubjectDN;

    public StatedumpCAIdChange(final int fromId, final int toId, final String toSubjectDN) {
        this.fromId = fromId;
        this.toId = toId;
        this.toSubjectDN = toSubjectDN;
    }

    public int getFromId() {
        return fromId;
    }

    public int getToId() {
        return toId;
    }

    public String getToSubjectDN() {
        return toSubjectDN;
    }

}
