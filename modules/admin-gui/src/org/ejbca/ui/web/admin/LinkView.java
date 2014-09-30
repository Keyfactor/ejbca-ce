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

package org.ejbca.ui.web.admin;

/**
 * Represents a link to another view. Used by approvals to link from approvals list to certificate views.
 * 
 * @version $Id$
 *
 */
public class LinkView {

	private String URI;
	private String preDescription;
	private String description;
	private String postDescription;

	public LinkView(String URI, String preDescription, String description, String postDescription) {
		this.URI = URI;
		this.preDescription = preDescription;
		this.description = description;
		this.postDescription = postDescription;
	}
	
	public String getURI() {
		return URI;
	}
	
	public String getPreDescription() {
		return preDescription;
	}

	public String getPostDescription() {
		return postDescription;
	}

	public String getDescription() {
		return description;
	}
}
