package se.anatom.ejbca.util.passgen;

/**
 * Digit4CharPasswordGenerator is a class generating random passwords containing four digits. 
 *
 * @version $Id: Digit4CharPasswordGenerator.java,v 1.2 2003-11-24 12:30:05 anatom Exp $
 */
public class Digit4CharPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    
    public static final int MIN_CHARS = 4;
    public static final int MAX_CHARS = 4;
    
    public Digit4CharPasswordGenerator(){
    	super(MIN_CHARS, MAX_CHARS, USEDCHARS);
    }
      
}
