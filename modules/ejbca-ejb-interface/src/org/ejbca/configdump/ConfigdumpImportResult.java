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
package org.ejbca.configdump;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.ejbca.configdump.ConfigDumpSetting.ItemKey;

/**
 * Holds information about the status of a Configdump import operation.
 * @version $Id$
 */
public final class ConfigdumpImportResult extends ConfigdumpResult {
    private static final long serialVersionUID = 1L;
    private final List<ItemKey> alreadyExistingItems;
    private final List<ItemKey> itemsRequiringPassword;
    
    public ConfigdumpImportResult(final List<String> reportedErrors, final List<String> reportedWarnings, final Set<ItemKey> alreadyExistingItems,
            final Set<ItemKey> itemsRequiringPassword) {
        super(reportedErrors, reportedWarnings);
        this.alreadyExistingItems = Collections.unmodifiableList(new ArrayList<>(alreadyExistingItems));
        this.itemsRequiringPassword = Collections.unmodifiableList(new ArrayList<>(itemsRequiringPassword));
    }
    
    public List<ItemKey> getAlreadyExistingItems() {
        return alreadyExistingItems;
    }
    
    public List<ItemKey> getItemsRequiringPassword() {
        return itemsRequiringPassword;
    }
}
