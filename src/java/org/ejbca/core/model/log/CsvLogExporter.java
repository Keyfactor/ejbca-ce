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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Exports a collection of log entries as, optionally signed, Comma Separated Values (CSV).
 * 
 * Depends on CAAdminSession for use of a CA's extended CMS service.
 * 
 * @version $Id$
 */
public class CsvLogExporter implements ILogExporter {
	
	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CsvLogExporter.class);
	
	private String signingCA = null;

	public CsvLogExporter(final String signingCA) {
		this.signingCA = signingCA;
	}

	/** @see org.ejbca.core.model.log.ILogExporter */
	@Override
	public byte[] export(final Admin admin, final Collection<LogEntry> logentries) throws Exception {
		log.trace(">export");
		byte[] ret = null;		
		if (logentries != null) {
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final PrintWriter pw = new PrintWriter(baos);
			try {
				for (final LogEntry next : logentries) {
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
		// Sign the result if we have a signing CA
		if (log.isDebugEnabled()) {
			log.debug("Signing CA is '"+signingCA+"'");    		
		}        	
		if (ret!=null && StringUtils.isNotEmpty(signingCA)) {
			try {
				final int caid = Integer.parseInt(signingCA);
				final CmsCAServiceRequest request = new CmsCAServiceRequest(ret, CmsCAServiceRequest.MODE_SIGN);
				final CAAdminSession caAdminSession = new EjbLocalHelper().getCaAdminSession();
				final CmsCAServiceResponse resp = (CmsCAServiceResponse) caAdminSession.extendedService(admin, caid, request);
				ret = resp.getCmsDocument();
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
		if (log.isTraceEnabled()) {
			int no = 0;
			if (logentries != null) {
				no = logentries.size();
			}
			log.trace("<export: "+no+" entries");
		}
		return ret;
	}
}
