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

import org.apache.log4j.Logger;

public class CsvLogExporter implements ILogExporter {
	
	/** Log4j logging */
	private static final Logger log = Logger.getLogger(CsvLogExporter.class);
	
	private Collection logentries = null;
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

	public String getSigningCA() {
		return signingCA;
	}
	
	public void setSigningCA(String ca) {
		this.signingCA = ca;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogExporter
	 */
	public byte[] export() {
		log.debug(">export");
		byte[] ret = null;		
		if (logentries != null) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			PrintWriter pw = new PrintWriter(baos);
			try {
				Iterator i = logentries.iterator();
				while (i.hasNext()) {
					LogEntry next = (LogEntry)i.next();
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
		log.debug("<export: "+no+" entries");
		return ret;
	}

}
