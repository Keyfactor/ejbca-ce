/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.admin.loginterface;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;

import org.ejbca.core.model.log.LogEntry;
import org.ejbca.ui.web.admin.rainterface.SortBy;


/**
 * A class representing a set of log entry view representations.
 * @author  TomSelleck
 * @version $Id: LogEntriesView.java 8667 2010-02-18 15:28:12Z anatom $
 */
public class LogEntriesView implements java.io.Serializable {
 
    /** Creates a new instance of LogEntriesView  */
    public LogEntriesView(SubjectDNProxy dnproxy , String[] localinfoeventnames, String[] localerroreventnames, String[] localsystemeventnames, String[] localmodulenames, HashMap caidtonamemap) {
      logentryviews = new ArrayList();
      sortby = new SortBy(SortBy.TIME, SortBy.DECENDING);
      this.dnproxy = dnproxy;
      this.localinfoeventnames=localinfoeventnames;
      this.localerroreventnames=localerroreventnames;
      this.localsystemeventnames=localsystemeventnames;
      this.localmodulenames=localmodulenames;
      this.caidtonamemap=caidtonamemap;
    }
    
    // Public methods.
    
    /**
     * Methods that sets the sorting preference and sortorder.
     *
     * @param sortby should be one of the constants defined in org.ejbca.ui.web.admin.rainterface.Sortby.
     * @param sortorder should be one of the constants defined in org.ejbca.ui.web.admin.rainterface.Sortby.
     */  
    public void sortBy(int sortby, int sortorder) {
      this.sortby.setSortBy(sortby);
      this.sortby.setSortOrder(sortorder);
      
      Collections.sort(logentryviews);
    }
    
    /**
     * Method that returns a given number of sorted logentryviews
     *   
     * @param index the startingpoint of the data.
     * @param size the number of logentryviews to return
     * @return an array of LogEntryView.
     **/
    public LogEntryView[] getEntries(int index, int size) {
      int endindex;  
      LogEntryView[] returnval;
   
      if (index > logentryviews.size()) {
    	  index = logentryviews.size()-1;
      }
      if (index < 0) {
    	  index =0;
      }
      
      endindex = index + size;
      if (endindex > logentryviews.size()) {
    	  endindex = logentryviews.size();
      }
      
      returnval = new LogEntryView[endindex-index];  
      
      int end = endindex - index;
      for (int i = 0; i < end; i++) {
        returnval[i] = (LogEntryView) logentryviews.get(index+i);   
      }
      
      return returnval;
    }
    
    /**
     * Method that clears the internal data and adds a collection of logentries.
     */ 
    public void setEntries(Collection logentries) throws RemoteException{ 
      LogEntryView logentryview;   
      Iterator i;  
      this.logentryviews.clear();
      if(logentries!=null && logentries.size() > 0){
        i=logentries.iterator();
        while(i.hasNext()){
          LogEntry nextentry = (LogEntry) i.next();  
          logentryview = new LogEntryView(nextentry, dnproxy, localinfoeventnames, localerroreventnames, localsystemeventnames, localmodulenames, caidtonamemap); 
          logentryview.setSortBy(this.sortby);
          logentryviews.add(logentryview);
        }
        Collections.sort(logentryviews);
      }
    }
    
    /**
     * Method that returns the number of available logentryviews. 
     */   
    public int size(){
      return logentryviews.size();   
    }
    // Private fields
    private ArrayList logentryviews;
    private SortBy sortby;
    private SubjectDNProxy dnproxy;
    private String[] localinfoeventnames;
    private String[] localerroreventnames;
    private String[] localsystemeventnames;
    private String[] localmodulenames;
    private HashMap  caidtonamemap;
}
