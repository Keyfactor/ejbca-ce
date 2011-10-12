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

import org.cesecore.audit.audit.AuditExporter;

/**
 * Dummy implementation of AuditExporter that does nothing.
 * 
 * Based on CESeCore version:
 *      AuditExporterDummy.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
public class AuditExporterDummy implements AuditExporter {

	@Override
	public void close() throws IOException {
	}

	@Override
	public void setOutputStream(OutputStream outputStream) throws IOException {
	}

	@Override
	public void writeEndObject() throws IOException {
	}

	@Override
	public void writeField(String key, long value) throws IOException {
	}

	@Override
	public void writeStartObject() throws IOException {
	}

	@Override
	public void writeField(String key, String value) throws IOException {
	}
	
    @Override
    public void startObjectLabel(String label) throws IOException {
    }

    @Override
    public void endObjectLabel() throws IOException {
    }
}
