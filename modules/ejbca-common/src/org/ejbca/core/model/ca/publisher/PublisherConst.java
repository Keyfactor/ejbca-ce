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

package org.ejbca.core.model.ca.publisher;

/**
 * Constants for Publishers. Constants for Type of publisher: Type is constructed as a mask
 * since one publisher can be of several types.
 * @version $Id$
 */
public class PublisherConst {
	
	/**Custom Publisher Container*/
	public static final int TYPE_CUSTOMPUBLISHERCONTAINER = 1;

    /**LDAP publisher*/
	public static final int TYPE_LDAPPUBLISHER = 2;
	
	/**Active Directory Publisher*/
	public static final int TYPE_ADPUBLISHER = 3;
	
	/**LDAP Search Publisher*/
	public static final int TYPE_LDAPSEARCHPUBLISHER = 4;
	
	/** 
	 * External OCSP Publisher
	 * 
	 * @deprecated This publisher type no longer exists in EJBCA
	 */
	@Deprecated
    public static final int TYPE_VAPUBLISHER = 5;

    /** Multi publisher */
    public static final int TYPE_MULTIGROUPPUBLISHER = 6;


	/**The entry has been published successfully*/
	public static final int STATUS_SUCCESS = 10; // If the entry has been published successfully
	
	/**Publishing should be retried*/
    public static final int STATUS_PENDING = 20; // If we should retry publishing
    
    /**Publishing failed*/
    public static final int STATUS_FAILED = 30; // If publishing failed completely so we will not try again
    
    
    
    /**A certificate published*/
    public static final int PUBLISH_TYPE_CERT = 1; // Is it a certificate we publish
    
    /**A CRL published*/
    public static final int PUBLISH_TYPE_CRL  = 2; // Is it a CRL we publish

}
