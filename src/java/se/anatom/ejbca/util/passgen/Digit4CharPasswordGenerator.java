package se.anatom.ejbca.util.passgen;

/**
 * Password4CharGenerator is a class generating random passwords containing four digits. 
 *
 * @version $Id: Digit4CharPasswordGenerator.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public class Digit4CharPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0'};
    
    public static final int MIN_CHARS = 4;
    public static final int MAX_CHARS = 4;
    
    public Digit4CharPasswordGenerator(){
    	super(MIN_CHARS, MAX_CHARS, USEDCHARS);
    }
      
}
