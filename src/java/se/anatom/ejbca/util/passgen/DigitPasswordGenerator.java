package se.anatom.ejbca.util.passgen;

/**
 * AllPrintablePasswordGenerator is a class generating random passwords containing  
 * DigitPasswordGenerator is a class generating random passwords containing 6-8 char 
 * digit passwords. 
 *
 * @version $Id: DigitPasswordGenerator.java,v 1.3 2003-12-05 14:49:10 herrvendil Exp $
 */
public class DigitPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    

    
    public DigitPasswordGenerator(){
    	super(USEDCHARS);
    }
      
}
