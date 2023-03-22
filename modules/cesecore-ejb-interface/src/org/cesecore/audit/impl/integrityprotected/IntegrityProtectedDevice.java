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
package org.cesecore.audit.impl.integrityprotected;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.AuditLogDevice;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.audit.log.AuditRecordStorageException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.time.TrustedTime;
import org.cesecore.util.query.QueryCriteria;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Log device using database configured integrity protection.
 * 
 * This implementation does not comply with all the CESeCore.FPT_CIMC_TSP.1.*:
 * FPT_CIMC_TSP.1.1:
 * "The TSF shall periodically create an audit log signing event in which it computes a digital signature, keyed hash,
 * or authentication code over the entries in the audit log."
 * This implementation complies if database integrity protection is enabled.
 * 
 * FPT_CIMC_TSP.1.2:
 * "The digital signature, keyed hash, or authentication code shall be computed over, at least, every entry that has
 * been added to the audit log since the previous audit log signing event and the digital signature, keyed hash, or
 * authentication code from the previous log signing event."
 * This implementation protects every single entry. A unique sequence number per cluster node and node identifier is
 * used as a part of the protected (e.g. signed) data. Given the private key or secret used to protect the data and
 * full database access, it is slightly computationally easier to falsify the audit trail than if the previous row's
 * signature or hash was included in the protected data. If the private key or secret used to protect the data is
 * compromised there is no real difference in how well (poorly) you can trust the audit trail. The solution implemented
 * here has significantly better performance, since we don't have to wait for the previous log event to complete before
 * we can start with the next one.
 * With a transactional database, the worst catastrophic fail would still never loose of the audit log for things that
 * have happened.
 * 
 * FTP_CIMC_TSP.1.3:
 * "The specified frequency at which the audit log singing event occurs shall be configurable."
 * This implementation supports every row or none.
 * 
 * FTP_CIMC_TSP.1.4:
 * "The digital signature, keyed hash, or authentication code from the audit log signing event shall be included in
 * the audit log."
 * This implementation makes this information available via AuditRecordData.getRowProtection() and this is also
 * included in exported log files.
 * 
 * @version $Id$
 */
public class IntegrityProtectedDevice implements AuditLogDevice {

	private Map<Class<?>, ?> ejbs;

	@Override
	public void setEjbs(Map<Class<?>, ?> ejbs) {
		this.ejbs = ejbs;
	}
	
	@SuppressWarnings("unchecked")
	private <T> T getEjb(Class<T> c) {
		return (T) ejbs.get(c);
	}

	@Override
	public AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport, Map<String, Object> signatureDetails, Properties properties, Class<? extends AuditExporter> c) throws AuditLogExporterException {
		return getEjb(IntegrityProtectedAuditorSessionLocal.class).exportAuditLogs(token, cryptoToken, timestamp, deleteAfterExport, signatureDetails, properties, c);
	}

	@Override
	public List<? extends AuditLogEntry> selectAuditLogs(AuthenticationToken token, int startIndex, int max, QueryCriteria criteria, Properties properties) {
		return getEjb(IntegrityProtectedAuditorSessionLocal.class).selectAuditLogs(token, startIndex, max, criteria, properties);
	}

	@Override
	public AuditLogValidationReport verifyLogsIntegrity(AuthenticationToken token, Date date, Properties properties) throws AuditLogValidatorException {
		return getEjb(IntegrityProtectedAuditorSessionLocal.class).verifyLogsIntegrity(token, date, properties);
	}

	@Override
	public void log(TrustedTime trustedTime, EventType eventType, EventStatus eventStatus, ModuleType module, ServiceType service, String authToken, String customId,
			String searchDetail1, String searchDetail2, Map<String, Object> additionalDetails, Properties properties) throws AuditRecordStorageException {
		getEjb(IntegrityProtectedLoggerSessionLocal.class).log(trustedTime, eventType, eventStatus, module, service, authToken, customId, searchDetail1, searchDetail2, additionalDetails, properties);
	}

	@Override
	public boolean isSupportingQueries() {
		return true;
	}

	@Override
	public void prepareReset() throws AuditLogResetException {
		// Do nothing.. we keep logging here, since there is no reasonable way to disable logging on all nodes
	}

	@Override
	public void reset() throws AuditLogResetException {
		/*
		 * This will not work in a clustered deployment! The only way to get this working would
		 * be to go outside the shared database model. (Reading last available sequenceNumber from
		 * db for each log write would kill performance and make it easier to remove the last log
		 * entries without it being noticed.)
		 */
		NodeSequenceHolder.INSTANCE.reset();
	}
}
