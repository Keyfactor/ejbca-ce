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
package org.ejbca.ui.cli.infrastructure;

/**
 * @version $Id$
 *
 */
public class CliUsernameException extends Exception {

    private static final long serialVersionUID = -390353232257435050L;

    public CliUsernameException() {
        super();
    }

    public CliUsernameException(String message, Throwable cause) {
        super(message, cause);
    }

    public CliUsernameException(String message) {
        super(message);
    }

    public CliUsernameException(Throwable cause) {
        super(cause);
    }

}
