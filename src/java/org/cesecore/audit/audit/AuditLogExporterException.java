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
package org.cesecore.audit.audit;

/**
 * Error during export of secure audit log events.
 * 
 * Based on cesecore:
 *      AuditLogExporterException.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 */
public class AuditLogExporterException extends Exception {

    private static final long serialVersionUID = -4260121156919588354L;
   
    public AuditLogExporterException() {
        super();
    }

    public AuditLogExporterException(final String message) {
        super(message);
    }

    public AuditLogExporterException(final String message, final Throwable throwable) {
        super(message, throwable);
    }

    public AuditLogExporterException(final Throwable throwable) {
        super(throwable);
    }
}
