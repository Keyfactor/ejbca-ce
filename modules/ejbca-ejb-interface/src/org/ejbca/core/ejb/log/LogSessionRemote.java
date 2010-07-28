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
package org.ejbca.core.ejb.log;

import javax.ejb.Remote;

/**
 * Remote interface for LogSession.
 */
@Remote
public interface LogSessionRemote extends LogSession {
    /**
     * Replace existing devices with a new one in this beans LogSession
     * reference. Used for testing, since the JUnit has to inject a mock
     * ProtectedLogDevice in both the instance accessed remotly and also the
     * local instance accessed by this bean to be able to use the container
     * managed transations.
     */
    public void setTestDeviceOnLogSession(Class implClass, String name);

    /**
     * Replace existing devices with the original ones in this beans LogSession
     * reference. Used for testing, since the JUnit has to inject a mock
     * ProtectedLogDevice in both the instance accessed remotly and also the
     * local instance accessed by this bean to be able to use the container
     * managed transations.
     */
    public void restoreTestDeviceOnLogSession();

}
