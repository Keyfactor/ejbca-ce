/*
 * LogMatch.java
 *
 * Created on den 28 aug 2002, 23:20
 */

package se.anatom.ejbca.util.query;

/**
 * A class used by Query class to build a query for ejbca log module. Inherits BasicMatch.
 * 
 *
 * Main function is getQueryString which returns a fragment of SQL statment.
 *
 * @see se.anatom.ejbca.util.query.BasicMatch
 * @see se.anatom.ejbca.util.query.TimeMatch
 * @see se.anatom.ejbca.util.query.LogMatch
 * @author  TomSelleck
 */
public class LogMatch extends BasicMatch {
    
    // Public Constants
    public final static int MATCH_WITH_USERNAME         = 0;
    public final static int MATCH_WITH_ADMINCERTIFICATE = 1;
    public final static int MATCH_WITH_IP               = 2;
    public final static int MATCH_WITH_SPECIALADMIN     = 3;   
    public final static int MATCH_WITH_CERTIFICATE      = 4; 
    public final static int MATCH_WITH_COMMENT          = 5; 
    public final static int MATCH_WITH_EVENT            = 6; // Value must the number representation.
    public final static int MATCH_WITH_MODULE           = 7;


    // Private Constants.
    private final static String[] MATCH_WITH_SQLNAMES = {"username", "adminData", "adminData", "adminType"
                                                         , "certificateSNR", "comment", "event", "module"}; // Represents the column names in ra userdata table.
   
    
    // Public methods.
    /** Creates a new instance of LogMatch.
     *
     *  @param matchwith determines which field i logentry table to match with.
     *  @param matchtype determines how to match the field..
     *  @param matchvalue the value to match with.
     * 
     *  @throws NumberFormatException if matchvalue constains illegal numbervalue when matching number field.
     */
    public LogMatch(int matchwith, int matchtype, String matchvalue) throws NumberFormatException {
      this.matchwith=matchwith;
      this.matchtype=matchtype;
      this.matchvalue=matchvalue;
      
      if(matchwith ==  MATCH_WITH_EVENT || matchwith ==  MATCH_WITH_SPECIALADMIN  )
        new Integer(matchvalue);
    }
    
    /**
     * Returns a SQL statement fragment from the given data.
     */
    public String getQueryString(){
      String returnval = "";
      
        if(matchtype == BasicMatch.MATCH_TYPE_EQUALS)
           returnval =  MATCH_WITH_SQLNAMES[matchwith] + " = '" + matchvalue + "'";              
        
        if(matchtype == BasicMatch.MATCH_TYPE_BEGINSWITH)
           returnval =  MATCH_WITH_SQLNAMES[matchwith] + " LIKE '" + matchvalue + "%'";  
      
        if(matchtype == BasicMatch.MATCH_TYPE_CONTAINS)
           returnval =  MATCH_WITH_SQLNAMES[matchwith] + " LIKE '%" + matchvalue + "%'";  
      
      return returnval;  
    } // getQueryString
    
    /** Checks if query data is ok. */  
    public boolean isLegalQuery(){         
      return !(matchvalue.trim().equals(""));
    }
    
    // Private Methods    

      // Private Fields.
    private int matchwith;
    private int matchtype;
    private String matchvalue;
}
