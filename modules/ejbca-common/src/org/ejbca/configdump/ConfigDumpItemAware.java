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

import java.io.Serializable;
import java.util.List;

/**
 * Config dump extension for map backed EJBCA objects.
 * 
 * @version $Id$
 */
public interface ConfigDumpItemAware {
    
    /**
     * Initializes the config dump properties.
     */
    void initConfigdumpProperties();
    
    /**
     * Returns the list of declared config dump properties.
     * @return the list of config dump properties or null.
     */
    List<ConfigdumpProperty<? extends Serializable>> getConfigDumpProperties();
}
