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
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.util.EjbLocalHelper;

public class CsvLogExporter implements ILogExporter {
	
	/** Log4j logging */
	private static final Logger log = Logger.getLogger(CsvLogExporter.class);
	
	private Collection<LogEntry> logentries = null;
	private String signingCA = null;
	
	/**
	 * @see org.ejbca.core.model.log.ILogExporter
	 */
	public void setEntries(Collection logentries) {
		this.logentries = logentries;
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogExporter
	 */
	public int getNoOfEntries() {
		if (logentries == null) {
			return 0;
		}
		return logentries.size();
	}

	/** Gets a CA used to create a signed CMS message of the log export, can be null for plain export
	 * 
	 * @return signCA CA (caid in string format, 12345) used to create a signed CMS message of the log export, or null for plain export
	 */
	public String getSigningCA() {
		return signingCA;
	}
	
	public void setSigningCA(String ca) {
		this.signingCA = ca;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogExporter
	 */
	public byte[] export(Admin admin) throws Exception {
		log.trace(">export");
		byte[] ret = null;		
		if (logentries != null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter pw = new PrintWriter(baos);
			try {
				Iterator<LogEntry> i = logentries.iterator();
				while (i.hasNext()) {
					LogEntry next = i.next();
					pw.print(next.getTime());
					pw.print("\t");
					pw.print(next.getAdminType());
					pw.print("\t");
					pw.print(next.getAdminData());
					pw.print("\t");
					pw.print(next.getCAId());
					pw.print("\t");
					pw.print(next.getModule());
					pw.print("\t");
					pw.print(next.getEvent());
					pw.print("\t");
					pw.print(next.getEventName());
					pw.print("\t");
					pw.print(next.getUsername());
					pw.print("\t");
					pw.print(next.getCertificateSNR());
					pw.print("\t");
					pw.print(next.getComment());
					pw.print("\t");
					pw.print(next.getVerifyResult());
					pw.print("\n");
				}
				pw.close();
				if (baos.size() > 0) {
					ret = baos.toByteArray();
				}
			} finally {
				try {
					pw.close();
					baos.close();
				} catch (IOException e) {
					log.error("Error closing ByteArrayOutputStream: ", e);
				}
			}
		}
		int no = getNoOfEntries();
		// Sign the result if we have a signing CA
		String ca = getSigningCA();
		if (log.isDebugEnabled()) {
			log.debug("Signing CA is '"+ca+"'");    		
		}        	
		if ( (ret != null) && StringUtils.isNotEmpty(ca) ) {
			try {
				int caid = Integer.parseInt(ca);
				CmsCAServiceRequest request = new CmsCAServiceRequest(ret, CmsCAServiceRequest.MODE_SIGN);
				//ISignSessionLocal signSession = ((ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME)).create();
				CmsCAServiceResponse resp = (CmsCAServiceResponse)new EjbLocalHelper().getCAAdminSession().extendedService(admin, caid, request);
				ret = resp.getCmsDocument();
			} catch (CreateException e) {
				log.error("Can not create sign session", e);
			} catch (IllegalExtendedCAServiceRequestException e) {
				log.error("Bad CA service", e);
			} catch (CADoesntExistsException e) {
				log.error("Bad CA", e);
			} catch (ExtendedCAServiceRequestException e) {
				log.error("", e);
			} catch (ExtendedCAServiceNotActiveException e) {
				throw e;
			}
		}
		log.trace("<export: "+no+" entries");
		return ret;
	}

}
