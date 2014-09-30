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
package org.ejbca.cesecoreintegration;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.ejb.Stateless;

import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.audit.AuditExporter;
import org.cesecore.audit.audit.AuditLogExportReport;
import org.cesecore.audit.audit.AuditLogExporterException;
import org.cesecore.audit.audit.AuditLogValidationReport;
import org.cesecore.audit.audit.AuditLogValidatorException;
import org.cesecore.audit.impl.queued.QueuedAuditorSessionLocal;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.query.QueryCriteria;

/**
 * Mock implementation of QueuedDevice interface to allow the secure audit code imported from
 * CESeCore to stay the same without bundling the queued implementation.
 * 
 * @version $Id$
 */
@Stateless
public class QueuedAuditorMockSessionBean implements QueuedAuditorSessionLocal {
	private static final String UNSUPPORTED = "Unsupported operation. QueuedDevice is not bundled with EJBCA.";
	
	@Override
	public void prepareReset() throws AuditLogResetException {
		throw new RuntimeException(UNSUPPORTED);
	}

	@Override
	public void reset() throws AuditLogResetException {
		throw new RuntimeException(UNSUPPORTED);
	}

	@Override
	public AuditLogExportReport exportAuditLogs(AuthenticationToken token, CryptoToken cryptoToken, Date timestamp, boolean deleteAfterExport,
			Map<String, Object> signatureDetails, Properties properties, Class<? extends AuditExporter> exporter) throws AuditLogExporterException {
		throw new RuntimeException(UNSUPPORTED);
	}

	@Override
	public List<? extends AuditLogEntry> selectAuditLogs(AuthenticationToken token, int startIndex, int max, QueryCriteria criteria, Properties properties) {
		throw new RuntimeException(UNSUPPORTED);
	}

	@Override
	public AuditLogValidationReport verifyLogsIntegrity(AuthenticationToken token, Date date, Properties properties) throws AuditLogValidatorException {
		throw new RuntimeException(UNSUPPORTED);
	}
	
    @Override
    public void delete(AuthenticationToken token, Date timestamp) {
        throw new RuntimeException(UNSUPPORTED);
    }

}
