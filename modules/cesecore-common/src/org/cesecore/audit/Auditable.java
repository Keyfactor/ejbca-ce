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
package org.cesecore.audit;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.query.QueryCriteria;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Interface for querying, validating and exporting log.
 * 
 * @version $Id$
 */
public interface Auditable {

    /**
     * Select a set of events to be audited.
     * 
     * @param token user performing the task.
     * @param startIndex Index where select will start.
     * @param max maximum number of results to be returned.
     * @param criteria Criteria defining the subset of logs to be selected.
     * @param properties properties to be passed on the device
     * 
     * @return The audit logs to the given criteria
     */
    List<? extends AuditLogEntry> selectAuditLogs(AuthenticationToken token, int startIndex, int max, QueryCriteria criteria, Properties properties);

    /**
     * This operation is used to export a set logs.
     * 
     * @param token user performing the task.
     * @param cryptoToken Crypto Token to be used.
     * @param timestamp Timestamp till which the logs will be exported.
     * @param deleteAfterExport Deletes the exported results if true.
     * @param signatureDetails Map containing signature details. {@see AuditLogBasicExporter public static varaibles}.
     * @param c the exporter implementation to be used
     * @param properties properties to be passed on the device
     * 
     * @return A extended validation report with the path to the exported file.
     * 
     * @throws AuditLogExporterException
     */
    AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport,
            Map<String, Object> signatureDetails, Properties properties, Class<? extends AuditExporter> exporter) throws AuditLogExporterException;

    /**
     * This operation is used to verify integrity of log to detect potential
     * modifications.
     * 
     * @param date Date from which to start verifying logs.
     * @param properties properties to be passed on the device
     * 
     * @return validation report.
     * @throws AuditLogValidatorException
     */
    AuditLogValidationReport verifyLogsIntegrity(AuthenticationToken token, Date date, Properties properties) throws AuditLogValidatorException;

}
