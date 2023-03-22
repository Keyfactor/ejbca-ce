/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.util;

import java.util.List;

import com.keyfactor.CesecoreException;

/**
 * The external process exception is the base exception to handle (platform dependent) external process calls ({@link ExternalProcessTools}. 
 * 
 * @version $Id$
 */
public class ExternalProcessException extends CesecoreException {

    private static final long serialVersionUID = 1L;

    private List<String> out;
    
    /**
     * Default constructor.
     */
    public ExternalProcessException() {
        super();
    }

    /**
     * Parameterized constructor.
     * @param message the message.
     * @param cause the cause
     */
    public ExternalProcessException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Parameterized constructor.
     * @param message the message.
     * @param cause the cause
     * @param out the list.
     */
    public ExternalProcessException(final String message, final Throwable cause, final List<String> out) {
        super(message, cause);
        this.out = out;
    }
    
    /**
     * Parameterized constructor.
     * @param message the message.
     */
    public ExternalProcessException(final String message) {
        super(message);
    }
    
    /**
     * Parameterized constructor.
     * @param message the message.
     * @param out the list.
     */
    public ExternalProcessException(final String message, final List<String> out) {
        super(message);
        this.out = out;
    }

    /**
     * Parameterized constructor.
     * @param cause the cause.
     */
    public ExternalProcessException(final Exception cause) {
        super(cause);
    }

    /**
     * Gets the list of exit code ({@link ExternalProcessTools#EXIT_CODE_PREFIX}), STDOUT and ERROUT.
     * @return the list.
     */
    public List<String> getOut() {
        return out;
    }

    /**
     * Sets the list of exit code ({@link ExternalProcessTools#EXIT_CODE_PREFIX}), STDOUT and ERROUT.
     * @param out the list.
     */
    public void setOut(List<String> out) {
        this.out = out;
    }
}
