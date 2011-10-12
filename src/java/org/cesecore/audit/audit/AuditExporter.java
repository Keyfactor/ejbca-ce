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

import java.io.IOException;
import java.io.OutputStream;

/**
 * Interface for how to export audit log data.
 * 
 * Users of this interface is expected to call:
 * 1. setOutputStream after creation
 * 2. For each added object:
 * 2a. writeStartObject()
 * 2b. zero or more writeLongField and/or writeStringField
 * 2c. writeEndObject()
 * 3. close()
 * 
 * Based on cesecore:
 *      AuditExporter.java 907 2011-06-22 14:42:15Z johane
 * 
 * @version $Id$
 */
public interface AuditExporter {

	void setOutputStream(OutputStream outputStream) throws IOException;
	void startObjectLabel(String label) throws IOException;
    void endObjectLabel() throws IOException;
	void writeStartObject() throws IOException;
	void writeField(String key, long value) throws IOException;
	void writeField(String key, String value) throws IOException;
	void writeEndObject() throws IOException;
	void close() throws IOException;
}
