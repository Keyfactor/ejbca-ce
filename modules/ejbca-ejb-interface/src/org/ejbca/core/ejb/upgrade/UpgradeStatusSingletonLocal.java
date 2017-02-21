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
package org.ejbca.core.ejb.upgrade;

import java.util.List;

import javax.ejb.Local;

/**
 * Local interface for UpgradeStatusSingletonBean.
 * 
 * @version $Id$
 */
@Local
public interface UpgradeStatusSingletonLocal {

    /** @return true of the post-upgrade is running as a background task on this node */
    boolean isPostUpgradeInProgress();

    /** @return Log4J logging events from UpgradeSessionBean while post-upgrade background task is running */
    List<org.apache.log4j.spi.LoggingEvent> getLogged();

    /** @return true if successfully claimed the node-local post-upgrade lock */
    boolean setPostUpgradeInProgressIfDifferent(boolean newValue);

    /** Reset the node-local post-upgrade lock */
    void resetPostUpgradeInProgress();

    /** Start listen to Log4J log events */
    void logAppenderAttach(org.apache.log4j.Logger log);

    /** Stop listen to Log4J log events */
    void logAppenderDetach(org.apache.log4j.Logger log);

}
