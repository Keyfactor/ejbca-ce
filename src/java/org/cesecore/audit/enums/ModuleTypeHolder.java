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
package org.cesecore.audit.enums;

/**
 * Simple implementation of ModuleType that holds the identifier.
 * 
 * Based on CESeCore version:
 *      ModuleTypeHolder.java 919 2011-07-01 11:19:33Z filiper
 * 
 * @version $Id$
 */
public class ModuleTypeHolder implements ModuleType {

	private static final long serialVersionUID = 1L;

	private final String value;
	
	public ModuleTypeHolder(final String value) {
		this.value = value;
	}
	
	@Override
	public String toString() {
		return value;
	}
	
	@Override
	public boolean equals(final ModuleType value) {
		if (value == null) {
			return false;
		}
		return this.value.toString().equals(value);
	}
}
