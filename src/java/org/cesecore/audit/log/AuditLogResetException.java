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
package org.cesecore.audit.log;

/**
 * Based on CESeCore version:
 *      AuditLogResetException.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
public class AuditLogResetException extends Exception {

	private static final long serialVersionUID = 1L;

	public AuditLogResetException() {
        super();
    }

    public AuditLogResetException(final String message) {
        super(message);
    }

    public AuditLogResetException(final Throwable t) {
        super(t);
    }

    public AuditLogResetException(final String s, final Throwable t) {
        super(s, t);
    }
}
