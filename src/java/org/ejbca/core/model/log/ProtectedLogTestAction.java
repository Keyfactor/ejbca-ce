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

import java.io.Serializable;

import org.apache.log4j.Logger;

/**
 * Stores the last taken action so that the JUnit test can read the result.
 * 
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogTestAction implements IProtectedLogAction, Serializable {

    private static final long serialVersionUID = -7056505975194222536L;

    private static final Logger log = Logger.getLogger(ProtectedLogTestAction.class);

    /**
     * @see org.ejbca.core.model.log.IProtectedLogAction
     */
    public void action(String causeIdentifier) {
        log.info("Setting cause to " + causeIdentifier);
        ProtectedLogTestActionResult.getInstance().setCause(causeIdentifier);
    }

    /**
     * @return the last status and then resets the status
     */
    public static String getLastActionCause() {
        log.info("Read cause " + ProtectedLogTestActionResult.getInstance().getCause());
        return ProtectedLogTestActionResult.getInstance().getCause();
    }
}
