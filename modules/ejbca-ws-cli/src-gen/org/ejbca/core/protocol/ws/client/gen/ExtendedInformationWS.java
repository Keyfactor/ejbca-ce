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

/**
 * Class used to represent extended information in userdata in the WebService API.
 * <br>&nbsp;<br>
 * Example code:<pre>
 *   UserDataVOWS user = new UserDataVOWS ();
 *   user.setUsername ("tester");
 *   user.setPassword ("foo123");
 *     .
 *     .
 *     .
 *   List&lt;ExtendedInformationWS&gt; ei = new ArrayList&lt;ExtendedInformationWS&gt; ();
 *   ei.add (new ExtendedInformationWS ("A name", "A value));
 *   ei.add (new ExtendedInformationWS ("Another name", "Another value"));
 *     .
 *     .
 *   user.setExtendedInformation (ei);
 *</pre>
 * 
 * @author Anders Rundgren
 * @version $Id$
 */
public class ExtendedInformationWS implements Serializable{
	
   /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

    private String name;
   
    private String value;
   
    /**
     * Emtpy constructor used by internally by web services
     */
    public ExtendedInformationWS(){}
    
	/**
	 * Constructor used when creating a new ExtendedInformationWS.
	 * 
	 * @param name Name (key) to set.
	 * @param value Value to set.
	 */
	public ExtendedInformationWS(String name, String value) {
		super();
		this.name = name;
		this.value = value;
	}

    
    /**
     * 
     * @return the name (key) property
     */
    public String getName (){
    	return this.name;
    }
    
    /**
      * @param name Name (key) to set
     */
    public void setName(String name){
      this.name = name;
    }
    

    /**
	 * @return the value property
	 */
	public String getValue() {
		return value;
	}


	/**
	 * @param value Value to set.
	 */
	public void setValue(String value) {
		this.value = value;
	}


}
