package se.anatom.ejbca.util.passgen;

/**
 * AllPrintablePasswordGenerator is a class generating random passwords containing 6 -8 char 
 * digit passwords. 
 *
 * @version $Id: DigitPasswordGenerator.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public class DigitPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    
    public static final int MIN_CHARS = 6;
    public static final int MAX_CHARS = 8;
    
    public DigitPasswordGenerator(){
    	super(MIN_CHARS, MAX_CHARS, USEDCHARS);
    }
      
}
