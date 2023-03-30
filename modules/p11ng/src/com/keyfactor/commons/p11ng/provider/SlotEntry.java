/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng.provider;

/**
 * Represents an entry in the HSM Slot with an alias and a type.
 *
 */
public class SlotEntry {

    private final String alias;
    private final String type;

    public SlotEntry(String alias, String type) {
        this.alias = alias;
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public String getAlias() {
        return this.alias;
    }    
}
