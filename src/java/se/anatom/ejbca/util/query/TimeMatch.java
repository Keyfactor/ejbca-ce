/*
 * TimeMatch.java
 *
 * Created on den 20 juli 2002, 23:20
 */

package se.anatom.ejbca.util.query;

import java.util.Date;

/**
 * A class used by Query class to build a query for ejbca log or ra modules. Inherits BasicMatch.
 * 
 *
 * Main function is getQueryString which returns a fragment of SQL statment.
 *
 * @see se.anatom.ejbca.util.query.BasicMatch
 * @see se.anatom.ejbca.util.query.UserMatch
 * @see se.anatom.ejbca.util.query.LogMatch
 * @author  TomSelleck
 */
public  class TimeMatch extends BasicMatch {
    
    // Public Constants
    public static final int MATCH_WITH_TIMECREATED  = 0;
    public static final int MATCH_WITH_TIMEMODIFIED = 1;

    // Private Constants.
    private final static String[] MATCH_WITH_SQLNAMES = {"time","time","timeCreated","timeModified"}; // Represents the column names in log/ra tables.
    
    // Public methods.
    /** Creates a new instance of TimeMatch.
     *  Construtor should only be used in ra user queries.
     *
     *  @param type uses Query class constants to determine if it's a log query or ra query.
     *  @param matchwith should be one of MATCH_WITH contants to determine with field to search. Only used in ra user queries.
     *  @param startdate gives a startdate for the query, null if not needed.
     *  @param startdate gives a enddate for the query, null if not needed.
     */
   public TimeMatch(int type, int matchwith, Date startdate, Date enddate) {
      this.type=type;
      this.matchwith=matchwith;
      this.startdate=startdate;
      this.enddate=enddate;
    }
    
    /** Creates a new instance of TimeMatch.
     *  Constructor should only be used in log queries.
     *  
     *  @param type uses Query class constants to determine if it's a log query or ra query.
     *  @param startdate gives a startdate for the query, null if not needed.
     *  @param startdate gives a enddate for the query, null if not needed.
     */
   public TimeMatch(int type, Date startdate, Date enddate) {
      this.type=type;
      this.matchwith=0;
      this.startdate=startdate;
      this.enddate=enddate;
    }   
   
   
    public String getQueryString(){
      String returnval = "( ";
      
      if(startdate!=null){
        returnval += MATCH_WITH_SQLNAMES[(type*2) + matchwith] + " >= " + startdate.getTime() + " ";
        if(enddate!=null)
          returnval += " AND ";   
      }
      if(enddate!=null){
        returnval += MATCH_WITH_SQLNAMES[(type*2) + matchwith] + " <= " + enddate.getTime() + " ";           
      }
      
      returnval += " )";
      return returnval;  
    } // getQueryString
    
    public boolean isLegalQuery(){
      return !(startdate==null && enddate==null);  
    }
    

    // Private Fields.
    private int matchwith;
    private int type;
    private Date startdate;
    private Date enddate;
}
