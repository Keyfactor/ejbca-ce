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

import java.security.cert.Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.query.QueryCriteria;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Allows auditing of securely logged events.
 * 
 * See {@link https
 * ://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_
 * (ADV_FSP)#Audit_Security_Events}
 * 
 * @version $Id$
 */
public interface SecurityEventsAuditorSession {

    /**
     * Select a set of events to be audited.
     * 
     * @param token identifier of the entity performing the task.
     * @param startIndex Index where select will start. Set to 0 to start from the beginning.
     * @param max maximum number of results to be returned. Set to 0 to use no limit.
     * @param criteria Criteria defining the subset of logs to be selected.
     * @param logDeviceId identifier of the AuditLogDevice
     * 
     * @return The audit logs to the given criteria
     * @throws AuthorizationDeniedException 
     */
    List<? extends AuditLogEntry> selectAuditLogs(AuthenticationToken token, int startIndex, int max, QueryCriteria criteria, String logDeviceId) throws AuthorizationDeniedException;

    /**
     * This operation is used to export a set logs.
     * 
     * @param token identifier of the entity performing the task.
     * @param cryptoToken Crypto Token to be used.
     * @param timestamp Timestamp till which the logs will be exported.
     * @param deleteAfterExport Deletes the exported results if true.
     * @param signatureDetails
     *            Map containing signature details used by the signer implementation.
     *            {@see SigningFileOutputStream public static variables for examples}.
     * @param logDeviceId identifier of the AuditLogDevice
     * 
     * @return A extended validation report with the path to the exported file.
     * 
     * @throws AuditLogExporterException
     * @throws AuthorizationDeniedException 
     */
    AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport,
            Map<String, Object> signatureDetails, String logDeviceId) throws AuditLogExporterException, AuthorizationDeniedException;

    /**
     * This operation is used to export a set logs.
     * 
     * @param token identifier of the entity performing the task.
     * @param cryptoToken Crypto Token to be used.
     * @param timestamp Timestamp till which the logs will be exported.
     * @param deleteAfterExport Deletes the exported results if true.
     * @param keyAlias alias identifying the key to be use in the file signature.
     * @param algorithm signature algorithm.
     * @param logDeviceId identifier of the AuditLogDevice
     * 
     * @return A extended validation report with the path to the exported file.
     * @throws AuditLogExporterException 
     * @throws AuthorizationDeniedException 
     */
    AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport,
            String keyAlias, String algorithm, String logDeviceId) throws AuditLogExporterException, AuthorizationDeniedException;

    /**
     * This operation is used to export a set logs.
     * 
     * @param token identifier of the entity performing the task.
     * @param cryptoToken Crypto Token to be used.
     * @param timestamp Timestamp till which the logs will be exported.
     * @param deleteAfterExport Deletes the exported results if true.
     * @param keyAlias alias identifying the key to be use in the file signature.
     * @param algorithm signature algorithm.
     * @param certificate certificate used in the signature.
     * @param logDeviceId identifier of the AuditLogDevice
     * 
     * @return A extended validation report with the path to the exported file.
     *
     * @throws AuditLogExporterException 
     * @throws AuthorizationDeniedException 
     */
    AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp, final boolean deleteAfterExport,
            final String keyAlias, final String algorithm, final Certificate certificate, String logDeviceId) throws AuditLogExporterException, AuthorizationDeniedException;

    /**
     * This operation is used to verify integrity of log to detect potential
     * modifications.
     * 
     * @param token identifier of the entity performing the task.
     * @param date Date from which to start verifying logs.
     * @param logDeviceId identifier of the AuditLogDevice
     * 
     * @return validation report.
     * @throws AuditLogValidatorException
     * @throws AuthorizationDeniedException 
     */
    AuditLogValidationReport verifyLogsIntegrity(AuthenticationToken token, Date date, String logDeviceId) throws AuditLogValidatorException, AuthorizationDeniedException;

    /** @return a Set of ids for AuditLogDevice that supports querying. */
	Set<String> getQuerySupportingLogDevices();
}
