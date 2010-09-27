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

package org.ejbca.core.ejb.log;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.OldLogConfiguration;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.protect.TableProtectSessionLocal;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.CertTools;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Session bean used by OldLogdevice.
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "OldLogSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OldLogSessionBean implements OldLogSessionLocal, OldLogSessionRemote {

	private static final Logger log = Logger.getLogger(OldLogSessionBean.class);
	
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

	@EJB
    private TableProtectSessionLocal tableProtectSession;

    /** If signing of logs is enabled of not, default not */
    private boolean logsigning = OldLogConfiguration.getLogSigning() || ProtectConfiguration.getLogProtectionEnabled();

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
		String uid = null;
		if (certificate != null) {
			uid = CertTools.getSerialNumberAsString(certificate) + "," + CertTools.getIssuerDN(certificate);        		
		}
		
		String admindata = admin.getAdminData();
		if((event == LogConstants.EVENT_INFO_ADMINISTRATORLOGGEDIN) && StringUtils.contains(comment, "external CA")){
			admindata += " : SubjectDN : \"" + CertTools.getSubjectDN(admin.getAdminInformation().getX509Certificate()) + "\"";
		}
		Integer id = getAndIncrementRowCount();
		entityManager.persist(new LogEntryData(id, admin.getAdminType(), admindata, caid, module, time, username, uid, event, comment));
		if (logsigning) {
			LogEntry le = new LogEntry(id.intValue(), admin.getAdminType(), admindata, caid, module, time, username, uid, event, comment);
			tableProtectSession.protect(le);
		}
	}

	public Collection<LogEntry> query(Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException {
		log.trace(">query()");
		if (capriviledges == null || capriviledges.length() == 0 || !query.isLegalQuery()) {
			throw new IllegalQueryException();
		}
		List<LogEntryData> logEntryDataList = LogEntryData.findByCustomQueryAndPrivileges(entityManager, query.getQueryString(), capriviledges, viewlogprivileges, maxResults+1);
		List<LogEntry> returnval = new ArrayList<LogEntry>();
		for (LogEntryData logEntryData : logEntryDataList) {
			LogEntry logEntry = logEntryData.getLogEntry();
			if (logsigning) {
				TableVerifyResult res = tableProtectSession.verify(logEntry);
				logEntry.setVerifyResult(res.getResultConstant());
			}
			returnval.add(logEntry);
		}
		return returnval;
	}

    private Integer getAndIncrementRowCount() {
    	LogConfigurationData logConfigurationData = LogConfigurationData.findByPK(entityManager, Integer.valueOf(0));
    	if (logConfigurationData == null) {
    		logConfigurationData = new LogConfigurationData(0, new LogConfiguration());
    		entityManager.persist(logConfigurationData);
    	}
        return logConfigurationData.getAndIncrementRowCount();
    }
}
