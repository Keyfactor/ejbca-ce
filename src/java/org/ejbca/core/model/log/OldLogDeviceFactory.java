/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.log;


/**
 * Factory for the old logging device.
 * @version $Id$
 */
public class OldLogDeviceFactory {
    /**
     * Creates a new OldLogDeviceFactory object.
     */
    public OldLogDeviceFactory() {
    }

    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @return An instance of the log device.
     */
    public synchronized ILogDevice makeInstance(String name)
            throws Exception {
        return OldLogDevice.instance(name);
    }

}
