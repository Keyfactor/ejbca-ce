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

/**
 * When we export logs we also validate them. This is an extension of the
 * validation report where the resulting exported files are available.
 * 
 * @version $Id$
 */
public class AuditLogExportReport extends AuditLogValidationReport {

	private static final long serialVersionUID = 1L;
	private String exportedFile;
	private String signatureFile;
	private int exportCount = 0;
	
	public AuditLogExportReport() {
		super();
	}

	/** Full pathname to the exported file, if any. */
	public void setExportedFile(final String exportedFile) {
		this.exportedFile = exportedFile;
	}

	/** @return Full pathname to the exported file, if any. */
	public String getExportedFile() {
		return exportedFile;
	}

	/** Full pathname to the signature of the exported file, if any. */
	public void setSignatureFile(final String signatureFile) {
		this.signatureFile = signatureFile;
	}

	/** @return Full pathname to the signature of the exported file, if any. */
	public String getSignatureFile() {
		return signatureFile;
	}

	/** Increase the number of exported log entries by one. */
	public void incExportCount() {
		exportCount++;
	}

	/** @return the number of exported log entries. */
	public int getExportCount() {
		return exportCount;
	}
}
