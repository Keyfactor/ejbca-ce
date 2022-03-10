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

/**
 * Holds information about the status of a Configdump import operation.
 * @version $Id$
 */
public final class ConfigdumpImportResult extends ConfigdumpResult {
    
    private static final long serialVersionUID = 1L;

    private final List<ConfigdumpItem<?>> problematicItems;
    private final List<ConfigdumpItem<?>> itemsRequiringPassword;
    
    public ConfigdumpImportResult(
            final List<String> reportedErrors,
            final List<String> reportedWarnings,
            final Set<ConfigdumpItem<?>> problematicItems,
            final Set<ConfigdumpItem<?>> itemsRequiringPassword
    ) {
        super(reportedErrors, reportedWarnings);
        this.problematicItems = Collections.unmodifiableList(new ArrayList<>(problematicItems));
        this.itemsRequiringPassword = Collections.unmodifiableList(new ArrayList<>(itemsRequiringPassword));
    }

    public List<ConfigdumpItem<?>> getProblematicItems() {
        return problematicItems;
    }
    
    public List<ConfigdumpItem<?>> getItemsRequiringPassword() {
        return itemsRequiringPassword;
    }
}
