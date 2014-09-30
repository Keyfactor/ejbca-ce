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
package org.ejbca.core;

/**
 * Exception to be thrown when a test cannot run due to setup difficulties. 
 * 
 * @version $Id$
 *
 */
public class TestAssertionFailedException extends RuntimeException {
    private static final long serialVersionUID = -8713408428524985390L;

    /**
     * 
     */
    public TestAssertionFailedException() {
    }

    /**
     * @param message
     */
    public TestAssertionFailedException(String message) {
        super(message);
    }

    /**
     * @param cause
     */
    public TestAssertionFailedException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     */
    public TestAssertionFailedException(String message, Throwable cause) {
        super(message, cause);
    }

}
