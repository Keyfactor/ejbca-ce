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
package org.cesecore.audit.impl;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;

import org.cesecore.audit.audit.AuditExporter;

/**
 * Simple implementation of AuditExporter that writes the field values as a
 * tab-separated file for easy import in spread sheet processors.
 * 
 * Based on CESeCore version:
 *      AuditExportCsv.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
public class AuditExportCsv implements AuditExporter {

	PrintWriter pw;
	boolean isThisLineEmpty;
	
	@Override
	public void close() throws IOException {
		pw.close();
	}

	@Override
	public void setOutputStream(OutputStream outputStream) throws IOException {
		pw = new PrintWriter(outputStream);
	}

	@Override
	public void writeEndObject() throws IOException {
		pw.println();
	}

	@Override
	public void writeField(String key, long value) throws IOException {
		printTab();
		pw.print(value);
		isThisLineEmpty = false;
	}

	@Override
	public void writeStartObject() throws IOException {
		isThisLineEmpty = true;
	}

	@Override
	public void writeField(String key, String value) throws IOException {
		printTab();
		pw.print(value);
		isThisLineEmpty = false;
	}

	/** Print a tab-char before the value if it is not the first one in this row. */
	private void printTab() {
		if (!isThisLineEmpty) {
			pw.print('\t');
		}
	}
}
