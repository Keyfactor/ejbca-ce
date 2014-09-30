/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ws.client.gen;

import java.io.Serializable;

/** Value object holding a Name and Id pair, for example for a CA or a end entity- or certificate profile.
 * 
 * @author Sebastien Levesque, Linagora. Javadoced by Tomas Gustavsson
 * @version $Id$
 */
public class NameAndId implements Serializable{

	/** Serial version UID, must be changed if class undergoes structural changes */
	private static final long serialVersionUID = 1734406078345094714L;
	
	/** A name, for example the name of a CA */
	private String name;
	/** An Id for example the CA-id */
	private int id;

	/**
	 * WS Constructor
	 */
	public NameAndId() {
		this.id = Integer.MIN_VALUE ;
		this.name = null;
	}
	
	public NameAndId(String name, int id) {
		this.name = name;
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

}
