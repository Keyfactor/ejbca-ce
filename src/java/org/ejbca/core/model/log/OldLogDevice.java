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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.OldLogConfiguration;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.log.LogConfigurationDataLocal;
import org.ejbca.core.ejb.log.LogConfigurationDataLocalHome;
import org.ejbca.core.ejb.log.LogEntryDataLocalHome;
import org.ejbca.core.ejb.protect.TableProtectSessionLocal;
import org.ejbca.core.ejb.protect.TableProtectSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implements a log device using the old logging system, implements the Singleton pattern.
 * @version $Id$
 */
public class OldLogDevice implements ILogDevice, Serializable {
	
	public final static String DEFAULT_DEVICE_NAME = "OldLogDevice";
	
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	private static final Logger log = Logger.getLogger(OldLogDevice.class);
	
    /** The home interface of SignSession session bean */
    private ISignSessionLocalHome signsessionhome;
    /** The come interface of the protection session bean */
    private TableProtectSessionLocalHome protecthome;
    /** The home interface of  LogEntryData entity bean */
    private LogEntryDataLocalHome logentryhome;
    /** The remote interface of the LogConfigurationData entity bean */
    private LogConfigurationDataLocal logconfigurationdata;
    /** The home interface of  LogConfigurationData entity bean */
    private LogConfigurationDataLocalHome logconfigurationhome;


	/**
	 * A handle to the unique Singleton instance.
	 */
	private static ILogDevice instance;

    /** Columns in the database used in select */
    private final String LOGENTRYDATA_TABLE = "LogEntryData";
    private final String LOGENTRYDATA_COL = "id, adminType, adminData, cAId, module, time, username, certificateSNR, event";
    private final String LOGENTRYDATA_TIMECOL = "time";
    // Different column names is an unfortunate workaround because of Oracle, you cannot have a column named 'comment' in Oracle.
    // The workaround 'comment_' was spread in the wild in 2005, so we have to use it so far.
    private final String LOGENTRYDATA_COL_COMMENT_OLD = "comment";
    private final String LOGENTRYDATA_COL_COMMENT_ORA = "comment_";

    private String deviceName = null;

    /** If signing of logs is enabled of not, default not */
    private boolean logsigning = OldLogConfiguration.getLogSigning() || ProtectConfiguration.getLogProtectionEnabled();

    /**
	 * Initializes
	 */
	protected OldLogDevice(String name) throws Exception {
		resetDevice(name);
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public void resetDevice(String name) {
		deviceName = name;
        logconfigurationhome = (LogConfigurationDataLocalHome) ServiceLocator.getInstance().getLocalHome(LogConfigurationDataLocalHome.COMP_NAME);
        logentryhome = (LogEntryDataLocalHome) ServiceLocator.getInstance().getLocalHome(LogEntryDataLocalHome.COMP_NAME);
        signsessionhome = (ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
        if (logsigning) {
        	protecthome = (TableProtectSessionLocalHome) ServiceLocator.getInstance().getLocalHome(TableProtectSessionLocalHome.COMP_NAME);
        }
	}

	/**
	 * Creates (if needed) the log device and returns the object.
	 *
	 * @param prop Arguments needed for the eventual creation of the object
	 * @return An instance of the log device.
	 */
	public static synchronized ILogDevice instance(String name) throws Exception {
		if (instance == null) {
			instance = new OldLogDevice(name);
		}
		return instance;
	}
	
    /**
     * Log everything in the database using the log entity bean
     */
	public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
		if (exception != null) {
			comment += ", Exception: " + exception.getMessage();
		}
		boolean successfulLog = false;
    	int tries = 0;
    	do{
    		try {
    			String uid = null;
    			if (certificate != null) {
    				uid = CertTools.getSerialNumberAsString(certificate) + "," + CertTools.getIssuerDN(certificate);        		
    			}
    			Integer id = getAndIncrementRowCount();
    			logentryhome.create(id, admin.getAdminType(), admin.getAdminData(), caid, module, time, username, uid, event, comment);
    			if (logsigning) {
    				LogEntry le = new LogEntry(id.intValue(), admin.getAdminType(), admin.getAdminData(), caid, module, time, username, uid, event, comment);
    				TableProtectSessionLocal protect = protecthome.create();
    				protect.protect(le);
    			}
    			successfulLog = true;
    		} catch (Throwable e) {
    			tries++;
    			if(tries == 3){
        			// We are losing a db audit entry in this case.
    				String msg = intres.getLocalizedMessage("log.errormissingentry");            	
    				log.error(msg,e);
    			}else{
    				String msg = intres.getLocalizedMessage("log.warningduplicatekey");            	
    				log.warn(msg);
    			}
    			
    		}
    	}while(!successfulLog && tries < 3);
    }

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public String getDeviceName() {
		return deviceName;
	}

	/**
	 * Method to export log records according to a customized query on the log db data. The parameter query should be a legal Query object.
	 *
	 * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
	 * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
	 * @param logexporter is the obbject that converts the result set into the desired log format 
	 * @return an exported byte array. Maximum number of exported entries is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT, returns null if there is nothing to export
	 * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
	 * @throws ExtendedCAServiceNotActiveException 
	 * @throws IllegalExtendedCAServiceRequestException 
	 * @throws ExtendedCAServiceRequestException 
	 * @throws CADoesntExistsException 
	 * @see org.ejbca.util.query.Query
	 */
	public byte[] export(Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter) throws IllegalQueryException, CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
		byte[] ret = null;
		if (query != null) {
			Collection logentries = query(query, viewlogprivileges, capriviledges);
			if (log.isDebugEnabled()) {
				log.debug("Found "+logentries.size()+" entries when exporting");    		
			}
			logexporter.setEntries(logentries);
			ret = logexporter.export();
			String ca = logexporter.getSigningCA();
			if (log.isDebugEnabled()) {
				log.debug("Signing CA is '"+ca+"'");    		
			}        	
			if ( (ret != null) && StringUtils.isNotEmpty(ca) ) {
				try {
					int caid = Integer.parseInt(ca);
					ISignSessionLocal sign = signsessionhome.create();
					CmsCAServiceRequest request = new CmsCAServiceRequest(ret, CmsCAServiceRequest.MODE_SIGN);
					CmsCAServiceResponse resp = (CmsCAServiceResponse)sign.extendedService(admin, caid, request);
					ret = resp.getCmsDocument();
				} catch (CreateException e) {
					log.error("Can not create sign session", e);
				}
			}
		}
		return ret;
	}

	/**
	 * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
	 *
	 * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
	 * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
	 * @return a collection of LogEntry. Maximum size of Collection is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT
	 * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
	 * @see org.ejbca.util.query.Query
	 */
	public Collection query(Query query, String viewlogprivileges, String capriviledges) throws IllegalQueryException {
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
			String sql = "select "+LOGENTRYDATA_COL+", "+LOGENTRYDATA_COL_COMMENT_OLD+" from "+LOGENTRYDATA_TABLE+" where ( "
			+ query.getQueryString() + ") and (" + capriviledges + ")";
			// Different column names is an unfortunate workaround because of Oracle, you cannot have a column named 'comment' in Oracle.
			// The workaround 'comment_' was spread in the wild in 2005, so we have to use it so far.
			if (!JDBCUtil.columnExists(con, LOGENTRYDATA_TABLE, LOGENTRYDATA_COL_COMMENT_OLD)) {
				log.debug("Using oracle column name 'comment_' in LogEntryData.");
				sql = StringUtils.replace(sql, LOGENTRYDATA_COL_COMMENT_OLD, LOGENTRYDATA_COL_COMMENT_ORA);
			}
			if (StringUtils.isNotEmpty(viewlogprivileges)) {
				sql += " and (" + viewlogprivileges + ")";
			}
			sql += " order by "+LOGENTRYDATA_TIMECOL+" desc";
			if (log.isDebugEnabled()) {
				log.debug("Query: "+sql);
			}
			ps = con.prepareStatement(sql);
			//ps.setFetchDirection(ResultSet.FETCH_REVERSE);
			ps.setFetchSize(LogConstants.MAXIMUM_QUERY_ROWCOUNT + 1);
			// Execute query.
			rs = ps.executeQuery();
			// Assemble result.
			ArrayList returnval = new ArrayList();
			while (rs.next() && returnval.size() <= LogConstants.MAXIMUM_QUERY_ROWCOUNT) {
				LogEntry data = new LogEntry(rs.getInt(1), rs.getInt(2), rs.getString(3), rs.getInt(4), rs.getInt(5), new Date(rs.getLong(6)), rs.getString(7), 
						rs.getString(8), rs.getInt(9), rs.getString(10));
				if (logsigning) {
					TableProtectSessionLocal protect = protecthome.create();
					TableVerifyResult res = protect.verify(data);
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
	} // query

    private Integer getAndIncrementRowCount() {
        if (this.logconfigurationdata == null) {
            try {
                logconfigurationdata = logconfigurationhome.findByPrimaryKey(new Integer(0));
            } catch (FinderException e) {
                try {
                    LogConfiguration logconfiguration = new LogConfiguration();
                    this.logconfigurationdata = logconfigurationhome.create(new Integer(0), logconfiguration);
                } catch (CreateException f) {
                    throw new EJBException(f);
                }
            }
        }

        return this.logconfigurationdata.getAndIncrementRowCount();
    }

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public void destructor() {
		// No action needed
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public boolean getAllowConfigurableEvents() {
		return true;
	}
    

}
