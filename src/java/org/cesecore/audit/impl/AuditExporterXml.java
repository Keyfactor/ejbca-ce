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

import java.beans.XMLEncoder;
import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;

import org.cesecore.audit.audit.AuditExporter;

/**
 * Exports audit log using the Java's XML serialization. A verbose format, but easy to use from Java applications.
 * 
 * Based on CESeCore version:
 *      AuditExporterXml.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
public class AuditExporterXml implements AuditExporter {

	private XMLEncoder encoder;
	private LinkedHashMap<String,Object> currentObject;
	
	@Override
	public void setOutputStream(final OutputStream outputStream) throws IOException {
		encoder = new XMLEncoder(outputStream);
	}

	@Override
	public void close() throws IOException {
		encoder.close();
	}

	@Override
	public void writeEndObject() throws IOException {
		encoder.writeObject(currentObject);
		encoder.flush();
		currentObject = null;
	}

	@Override
	public void writeField(String key, long value) throws IOException {
		currentObject.put(key, Long.valueOf(value));
	}

	@Override
	public void writeStartObject() throws IOException {
		currentObject = new LinkedHashMap<String,Object>();
	}

	@Override
	public void writeField(String key, String value) throws IOException {
		currentObject.put(key, value);
	}
}
