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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.OldLogConfiguration;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.protect.TableProtectSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
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
    private static final InternalResources intres = InternalResources.getInstance();
	
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

	@EJB
    private TableProtectSessionLocal tableProtectSession;

    /** Columns in the database used in select */
    private final String LOGENTRYDATA_TABLE = "LogEntryData";
    private final String LOGENTRYDATA_COL = "id, adminType, adminData, cAId, module, time, username, certificateSNR, event";
    private final String LOGENTRYDATA_TIMECOL = "time";
    private final String LOGENTRYDATA_COL_COMMENT = "logComment";

    /** If signing of logs is enabled of not, default not */
    private boolean logsigning = OldLogConfiguration.getLogSigning() || ProtectConfiguration.getLogProtectionEnabled();

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
		String uid = null;
		if (certificate != null) {
			uid = CertTools.getSerialNumberAsString(certificate) + "," + CertTools.getIssuerDN(certificate);        		
		}
		
		String admindata = admin.getAdminData();
		if((event == LogConstants.EVENT_INFO_ADMINISTRATORLOGGEDIN) && comment.contains("external CA")){
			admindata += ": CertDN : \"" + CertTools.getSubjectDN(admin.getAdminInformation().getX509Certificate()) + "\"";
		}
		Integer id = getAndIncrementRowCount();
		entityManager.persist(new LogEntryData(id, admin.getAdminType(), admindata, caid, module, time, username, uid, event, comment));
		if (logsigning) {
			LogEntry le = new LogEntry(id.intValue(), admin.getAdminType(), admindata, caid, module, time, username, uid, event, comment);
			tableProtectSession.protect(le);
		}
	}

	public Collection query(Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException {
		log.trace(">query()");
		if (capriviledges == null || capriviledges.length() == 0 || !query.isLegalQuery()) {
			throw new IllegalQueryException();
		}

		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			// Construct SQL query.
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql = "select "+LOGENTRYDATA_COL+", "+LOGENTRYDATA_COL_COMMENT+" from "+LOGENTRYDATA_TABLE+" where ( "
				+ query.getQueryString() + ") and (" + capriviledges + ")";
			if (StringUtils.isNotEmpty(viewlogprivileges)) {
				sql += " and (" + viewlogprivileges + ")";
			}
			sql += " order by "+LOGENTRYDATA_TIMECOL+" desc";
			if (log.isDebugEnabled()) {
				log.debug("Query: "+sql);
			}
			ps = con.prepareStatement(sql);
			//ps.setFetchDirection(ResultSet.FETCH_REVERSE);
			ps.setFetchSize(maxResults + 1);
			// Execute query.
			rs = ps.executeQuery();
			// Assemble result.
			ArrayList<LogEntry> returnval = new ArrayList<LogEntry>();
			while (rs.next() && returnval.size() <= maxResults) {
				LogEntry data = new LogEntry(rs.getInt(1), rs.getInt(2), rs.getString(3), rs.getInt(4), rs.getInt(5), new Date(rs.getLong(6)), rs.getString(7), 
						rs.getString(8), rs.getInt(9), rs.getString(10));
				if (logsigning) {
					//TableProtectSessionLocal protect = protecthome.create();
					TableVerifyResult res = tableProtectSession.verify(data);
					data.setVerifyResult(res.getResultConstant());
				}
				returnval.add(data);
			}
			return returnval;

		} catch (Exception e) {
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
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
