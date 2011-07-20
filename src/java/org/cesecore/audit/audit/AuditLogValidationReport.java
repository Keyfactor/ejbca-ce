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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

/**
 * This class represents the audit log validation report. 
 * It's generated during validation.
 *
 * Based on cesecore:
 *      AuditLogValidationReport.java 897 2011-06-20 11:17:25Z johane
 *
 * @version $Id$
 */
public class AuditLogValidationReport implements Serializable{

    private static final Logger log = Logger.getLogger(AuditLogValidationReport.class);
    private static final long serialVersionUID = 1L;
    
    private final List<AuditLogReportElem> errors;
    private final List<AuditLogReportElem> warns;
    
    public AuditLogValidationReport() {
        this.errors = new ArrayList<AuditLogReportElem>();
        this.warns = new ArrayList<AuditLogReportElem>();
    }

    /** @return list of errors in this report. */
    public List<AuditLogReportElem> errors() {
        return errors;
    }

    /**
     * Add a new error to the report list
     * @param error The error to be added.
     */
    public void error(final AuditLogReportElem error) {
    	log.warn(String.format("ERROR: auditlog sequence: %d -> %d. Reason: %s", error.getFirst(), error.getSecond(), error.getReasons()));
        this.errors.add(error);
    }

    /** @return a list of warnings in this report. */
    public List<AuditLogReportElem> warnings() {
        return this.warns;
    }

    /**
     * Add a new warning to the report.
     * @param warning The warning.
     */
    public void warn(final AuditLogReportElem warning){
    	log.info(String.format("WARN: auditlog sequence: %d -> %d. Reason: %s", warning.getFirst(), warning.getSecond(), warning.getReasons()));
        this.warns.add(warning);
    }
}
