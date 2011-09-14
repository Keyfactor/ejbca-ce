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
package org.cesecore.dbprotection;

/**
 * Wrapper for StringBuilder that inserts a separator between elements.
 * @version $Id$
 */
public class ProtectionStringBuilder {

	private static final long serialVersionUID = 1L;
	private static final String SEPARATOR_TAG = "<sep/>";
	
	private final StringBuilder sb;

	public ProtectionStringBuilder() {
		sb = new StringBuilder();
	}

	public ProtectionStringBuilder(final int initialCapacity) {
		sb = new StringBuilder(initialCapacity);
	}

	public ProtectionStringBuilder append(final Object o) {
		if (sb.length()>0) {
			sb.append(SEPARATOR_TAG);
		}
		// String.valueOf(o) would return "null" when null, which is not the same as null.
		if (o != null) {
			sb.append(o.toString());
		}
		return this;
	}

	public int length() {
		return sb.length();
	}
	
	@Override
	public String toString() {
		return sb.toString();
	}
}
