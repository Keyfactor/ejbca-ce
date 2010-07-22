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

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;

/**
 * Exports the given log-events as a CMS/PKCS7-file signed by a configured CA with CMS services enabled.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogCMSExportHandler implements IProtectedLogExportHandler, Serializable {

	private static final Logger log = Logger.getLogger(ProtectedLogCMSExportHandler.class);

	private static Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
	
	private ICAAdminSessionLocal caAdminSession = null;
	private ISignSessionLocal signSession = null;

	private ByteArrayOutputStream baos = null;
	private int exportingCAId = -1;
	private String filename = null;
	
	private ICAAdminSessionLocal getCAAdminSession() {
		try {
			if (caAdminSession == null) {
				caAdminSession = ((ICAAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME)).create();
			}
			return caAdminSession;
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}
	
	private ISignSessionLocal getSignSession() {
		try {
			if (signSession == null) {
				signSession = ((ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME)).create();
			}
			return signSession;
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void init(long exportEndTime, long exportStartTime, boolean forced) {
		String exportPath = ProtectedLogConfiguration.getCMSExportPath();
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd_HH.mm.ss.SSS");
		filename = exportPath + sdf.format(new Date(exportEndTime)) + (forced ? ".FORCED" : "")+".p7m";
		String exportingCA = ProtectedLogConfiguration.getCMSCaName();
		CAInfo caInfo = getCAAdminSession().getCAInfo(internalAdmin, exportingCA);
		if (caInfo != null) {
			exportingCAId = caInfo.getCAId();
		} else {
			log.error("No valid CA configured to use with CMS export.");
		}
		baos = new ByteArrayOutputStream();
	}
	
	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean done(String currentHashAlgorithm, byte[] exportedHash, byte[] lastExportedHash) {
		log.trace(">done");
		try {
			// Since we write everything at once, it will take up a lot of memory..
			log.debug("Sending "+baos.size()+" bytes to CMS service..");
			CmsCAServiceRequest request = new CmsCAServiceRequest(baos.toByteArray(), CmsCAServiceRequest.MODE_SIGN);
			CmsCAServiceResponse resp = (CmsCAServiceResponse) getSignSession().extendedService(internalAdmin, exportingCAId, request);
			byte[] export = resp.getCmsDocument();
			log.debug("Writing "+export.length+" bytes to file..");
			FileOutputStream fos = new FileOutputStream(filename);
			fos.write(export);
			fos.close();
			log.info("Export to  \"" + filename + "\"  complete.");
			return true;
		} catch (Exception e) {
			log.error(e);
		}
		log.trace("<done");
		return false;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean update(int adminType, String adminData, int caid, int module, long eventTime, String username, String certificateSerialNumber, String certificateIssuerDN, int eventId, String eventComment) {
		PrintWriter pw = new PrintWriter(baos);
		pw.print(eventTime);
		pw.print("\t");
		pw.print(adminType);
		pw.print("\t");
		pw.print(adminData);
		pw.print("\t");
		pw.print(caid);
		pw.print("\t");
		pw.print(module);
		pw.print("\t");
		pw.print(eventId);
		pw.print("\t");
		pw.print(LogEntry.getEventName(eventId));
		pw.print("\t");
		pw.print(username);
		pw.print("\t");
		pw.print(certificateSerialNumber);
		pw.print("\t");
		pw.print(eventComment);
		pw.print("\n");
		pw.close();
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void abort() {
		log.info("Export aborted.");
	}

}
