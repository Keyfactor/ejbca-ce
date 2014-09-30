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
 
/*
 * SortBy.java
 *
 * Created on den 18 april 2002, 15:47
 */

package org.ejbca.ui.web.admin.rainterface;

/**
 * A class specifying which field to sort the userdata by. 
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class SortBy implements java.io.Serializable {
    private static final long serialVersionUID = -2924038902779549663L;
    // Public constants
      // Constants used by userdata.
    public static final int USERNAME         = 0;
    public static final int PASSWORD         = 1;
    public static final int COMMONNAME       = 2;
    public static final int SERIALNUMBER     = 3;  
    public static final int TITLE            = 4;        
    public static final int ORGANIZATIONUNIT = 5;
    public static final int ORGANIZATION     = 6;
    public static final int LOCALE           = 7;
    public static final int STATE            = 8;
    public static final int DOMAINCOMPONENT  = 9;      
    public static final int COUNTRY          = 10;
    public static final int EMAIL            = 11;
    public static final int STATUS           = 12; 
    public static final int TIMECREATED      = 13;     
    public static final int TIMEMODIFIED     = 14;     
    public static final int CA               = 15;    
      // Constants used by logentrydata. 

    public static final int ADMINTYPE        = 1;
    public static final int ADMINDATA        = 2;
    public static final int MODULE           = 4;
    public static final int TIME             = 5;
    public static final int CERTIFICATE      = 6;    
    public static final int EVENT            = 7;     
    public static final int COMMENT          = 8;     
    
    public static final int ACCENDING        = 0;
    public static final int DECENDING        = 1;

    
    /** Creates a new instance of SortBy */
    public SortBy() {
      this.sortby=USERNAME;
      this.sortorder=ACCENDING;
    }
    
    public SortBy(int sortby, int sortorder){
      this.sortby=sortby;   
      this.sortorder=sortorder;
    }
    
    public int getSortBy() {
      return sortby;
    }
    
    public int getSortOrder() {
      return sortorder;
    }
    
    public void setSortBy(int sortby) {
       this.sortby=sortby;      
    }

    public void setSortOrder(int sortorder){
      this.sortorder=sortorder;        
    }
    // Private fields.
    private int sortby;
    private int sortorder;
}
