package se.anatom.ejbca.util.passgen;

/**
 * DigitPasswordGenerator is a class generating random passwords containing 6-8 char 
 * digit passwords. 
 *
 * @version $Id: DigitPasswordGenerator.java,v 1.2 2003-11-24 12:30:05 anatom Exp $
 */
public class DigitPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    
    public static final int MIN_CHARS = 6;
    public static final int MAX_CHARS = 8;
    
    public DigitPasswordGenerator(){
    	super(MIN_CHARS, MAX_CHARS, USEDCHARS);
    }
      
}
