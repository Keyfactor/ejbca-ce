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
package org.cesecore.audit.impl.log4j;

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Appender;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.ErrorHandler;
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
import org.cesecore.util.ValidityDate;
import org.cesecore.util.query.QueryCriteria;

import com.keyfactor.util.keys.token.CryptoToken;

/**
 * Simple implementation of (secure) audit that writes all log to Log4J.
 * 
 * This implementation does not comply to the CESeCore TSF regarding log protection and only provided as a compliment
 * to monitor operations or for use in high performance environments where compliance is not an issue.
 * 
 * @version $Id$
 */
public class Log4jDevice implements AuditLogDevice {

	private static final Logger LOG = Logger.getLogger(Log4jDevice.class);
	private static final String UNSUPPORTED = Log4jDevice.class.getSimpleName() + " does not support query, verification or export operations.";
	private final List<Log4jDeviceErrorHandler> errorHandlers = new ArrayList<Log4jDeviceErrorHandler>();
	
	public Log4jDevice() {
		@SuppressWarnings("unchecked")
        final Enumeration<Appender> enumeration = LOG.getAllAppenders();
		while (enumeration.hasMoreElements()) {
			final Appender appender = enumeration.nextElement();
			final ErrorHandler errorHandler = appender.getErrorHandler();
			if (errorHandler != null) {
				final Log4jDeviceErrorHandler wrappedErrorHandler = new Log4jDeviceErrorHandler(errorHandler);
				errorHandlers.add(wrappedErrorHandler);
				appender.setErrorHandler(wrappedErrorHandler);
			}
		}
	}
	
	private void assertNoErrors() throws AuditRecordStorageException {
		for (final Log4jDeviceErrorHandler errorHandler : errorHandlers) {
			if (!errorHandler.isOk()) {
				throw new AuditRecordStorageException("A log4j device failed to log.");
			}
		}
	}

	@Override
	public boolean isSupportingQueries() {
		return false;
	}

	@Override
	public void setEjbs(final Map<Class<?>, ?> ejbs) {
		// Does not use any beans
	}

	@Override
	public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp,
			final boolean deleteAfterExport, final Map<String, Object> signatureDetails, final Properties properties, final Class<? extends AuditExporter> c) throws AuditLogExporterException {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public List<? extends AuditLogEntry> selectAuditLogs(final AuthenticationToken token, final int startIndex, final int max, final QueryCriteria criteria, final Properties properties) {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public AuditLogValidationReport verifyLogsIntegrity(final AuthenticationToken token, final Date date, final Properties properties) throws AuditLogValidatorException {
		throw new UnsupportedOperationException(UNSUPPORTED);
	}

	@Override
	public void log(final TrustedTime trustedTime, final EventType eventType, final EventStatus eventStatus, final ModuleType module, final ServiceType service,
			final String authToken, final String customId, final String searchDetail1, final String searchDetail2, final Map<String, Object> additionalDetails, Properties properties)
			throws AuditRecordStorageException {
	    // Log lines are usually between 117 and 1700 bytes. An initial length of 1024 will cover most of them, speeding things up.
		final StringBuilder sb = new StringBuilder(1024);
		if (trustedTime != null) {
			sb.append(ValidityDate.formatAsISO8601(trustedTime.getTime(), ValidityDate.TIMEZONE_SERVER));
		}
		appendIfNotNull(sb, eventType);
		appendIfNotNull(sb, eventStatus);
		appendIfNotNull(sb, module);
		appendIfNotNull(sb, service);
		appendIfNotNull(sb, authToken);
		appendIfNotNull(sb, customId);
		appendIfNotNull(sb, searchDetail1);
		appendIfNotNull(sb, searchDetail2);
		if (additionalDetails != null) {
			for (final String detail : additionalDetails.keySet()) {
				if (sb.length()!=0) {
					sb.append(';');
				}
				sb.append(detail).append('=');
				final Object o = additionalDetails.get(detail);
				if (o != null) {
					sb.append(o.toString());
				}
			}
		}
		LOG.info(sb.toString());
		assertNoErrors();
	}
	
	// TODO: Not perfect for parsing, since any of the appended values might contain a ';' char
	private void appendIfNotNull(final StringBuilder sb, final Object o) {
		if (sb.length()!=0) {
			sb.append(';');
		}
		if (o != null) {
			sb.append(o.toString());
		}
	}

	@Override
	public void prepareReset() throws AuditLogResetException {
		// No action required
	}

	@Override
	public void reset() throws AuditLogResetException {
		// No action required
	}
}
