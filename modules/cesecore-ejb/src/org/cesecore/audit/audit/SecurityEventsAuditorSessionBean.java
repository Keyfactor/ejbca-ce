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
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.audit.AuditDevicesConfig;
import org.cesecore.audit.AuditLogEntry;
import org.cesecore.audit.impl.integrityprotected.IntegrityProtectedAuditorSessionLocal;
import org.cesecore.audit.impl.queued.QueuedAuditorSessionLocal;
import org.cesecore.audit.log.AuditLogResetException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AuditLogRules;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.query.QueryCriteria;

/**
 * This class handles secure logs auditing. This class is responsible for checking
 * authorization and delegating a request to the right implementation.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "SecurityEventsAuditorSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class SecurityEventsAuditorSessionBean implements SecurityEventsAuditorSessionLocal, SecurityEventsAuditorSessionRemote {
	
	private static final Logger LOG = Logger.getLogger(SecurityEventsAuditorSessionBean.class);

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private IntegrityProtectedAuditorSessionLocal integrityProtectedAuditorSession;
    @EJB
    private QueuedAuditorSessionLocal queuedAuditorSession;
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Set<String> getQuerySupportingLogDevices() {
    	return AuditDevicesConfig.getQuerySupportingDeviceIds();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<? extends AuditLogEntry> selectAuditLogs(final AuthenticationToken token, final int startIndex, final int max, final QueryCriteria criteria, final String logDeviceId) throws AuthorizationDeniedException {
        assertAuthorization(token, AuditLogRules.VIEW.resource());
    	return AuditDevicesConfig.getDevice(getEjbs(), logDeviceId).selectAuditLogs(token, startIndex, max, criteria, AuditDevicesConfig.getProperties(logDeviceId));
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp,
            final boolean deleteAfterExport, final String keyAlias, final String algorithm, final String logDeviceId) throws AuditLogExporterException, AuthorizationDeniedException {
        final HashMap<String, Object> details = new LinkedHashMap<String, Object>();
        details.put(SigningFileOutputStream.EXPORT_SIGN_KEYALIAS, keyAlias);
        details.put(SigningFileOutputStream.EXPORT_SIGN_ALG, algorithm);
        return exportAuditLogs(token, cryptoToken, timestamp, deleteAfterExport, details, logDeviceId);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp,
            final boolean deleteAfterExport, final String keyAlias, final String algorithm, final Certificate certificate, final String logDeviceId)
            throws AuditLogExporterException, AuthorizationDeniedException {
        final HashMap<String, Object> details = new LinkedHashMap<String, Object>();
        details.put(SigningFileOutputStream.EXPORT_SIGN_KEYALIAS, keyAlias);
        details.put(SigningFileOutputStream.EXPORT_SIGN_ALG, algorithm);
        details.put(SigningFileOutputStream.EXPORT_SIGN_CERT, certificate);
        return exportAuditLogs(token, cryptoToken, timestamp, deleteAfterExport, details, logDeviceId);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AuditLogExportReport exportAuditLogs(final AuthenticationToken token, final CryptoToken cryptoToken, final Date timestamp,
            final boolean deleteAfterExport, final Map<String, Object> signatureDetails, final String logDeviceId) throws AuditLogExporterException, AuthorizationDeniedException {
    	// StandardRules.AUDITLOGEXPORT export implies StandardRules.AUDITLOGVERIFY.
        assertAuthorization(token, AuditLogRules.EXPORT_LOGS.resource());
        LOG.info("Export of audit logs from device " + logDeviceId + " requested.");
        final Class<? extends AuditExporter> exporter = AuditDevicesConfig.getExporter(logDeviceId);
        final Properties properties = AuditDevicesConfig.getProperties(logDeviceId);
    	return AuditDevicesConfig.getDevice(getEjbs(), logDeviceId).exportAuditLogs(token, cryptoToken, timestamp, deleteAfterExport, signatureDetails, properties, exporter);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AuditLogValidationReport verifyLogsIntegrity(final AuthenticationToken token, final Date timestamp, final String logDeviceId) throws AuditLogValidatorException, AuthorizationDeniedException {
    	assertAuthorization(token, AuditLogRules.VERIFY.resource());
        LOG.info("Validation of audit logs in device " + logDeviceId + " requested.");
    	return AuditDevicesConfig.getDevice(getEjbs(), logDeviceId).verifyLogsIntegrity(token, timestamp, AuditDevicesConfig.getProperties(logDeviceId));
    }


	@Override
	public void prepareReset() throws AuditLogResetException {
		LogServiceState.INSTANCE.disable();
        for (final String loggerId : AuditDevicesConfig.getAllDeviceIds()) {
    		AuditDevicesConfig.getDevice(getEjbs(), loggerId).prepareReset();
        }
	}

	@Override
	public void reset() throws AuditLogResetException {
        for (final String loggerId : AuditDevicesConfig.getAllDeviceIds()) {
    		AuditDevicesConfig.getDevice(getEjbs(), loggerId).reset();
        }
        //should be called after the reset because if we enable log before might happen that a log call runs before reset
        LogServiceState.INSTANCE.enable();
	}

	/** Assert that we are authorized to the requested resource. */
    private void assertAuthorization(final AuthenticationToken token, final String accessRule) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(token, accessRule)) {
			throw new AuthorizationDeniedException("not authorized to: "+ token.toString());				
		} 
    }

    /**
     * Propagate the injected SSBs, since we can't use application server agnostic EJB lookup in EJB 3.0.
     * With EJB 3.1 this should be delegated to each implementation where the implementation specific SSBs
     * can be looked up.
     */
    private Map<Class<?>, Object> getEjbs() {
    	final Map<Class<?>, Object> ejbs = new HashMap<Class<? extends Object>, Object>();
    	ejbs.put(IntegrityProtectedAuditorSessionLocal.class, integrityProtectedAuditorSession);
    	ejbs.put(QueuedAuditorSessionLocal.class, queuedAuditorSession);
    	return ejbs;
    }
}
