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
 package org.ejbca.ui.web;

/**
 * Used for parameter errors on web pageges.
 * @author lars
 *
 */
public class ParameterError extends Exception {

    /**
     * @param message string to be displayed on the error page of the admin web GUI.
     */
    public ParameterError(String message) {
        super(message);
    }
}
