package se.anatom.ejbca.util.passgen;

/**
 * LettersAndDigitsPasswordGenerator is a class generating random passwords containing 6 - 8  letters 
 * or digits.
 * 
 * @version $Id: LettersAndDigitsPasswordGenerator.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public class LettersAndDigitsPasswordGenerator extends BasePasswordGenerator{
    
    private static final char[] USEDCHARS = {'1','2','3','4','5','6','7','8','9','0',
    	                                                              'q','Q','w','W','e','E','r','R','t','T',
    	                                                              'y','Y','u','U','i','I','o','O','p','P','a',
    	                                                             'A','s','S','d','D','f','F','g','G','h','H',
    	                                                             'j','J','k','K','l','L','z','Z','x','X','c','C',
    	                                                             'v','V','b','B','n','N','m','M'};
    
    public static final int MIN_CHARS = 6;
    public static final int MAX_CHARS = 8;
    
    public LettersAndDigitsPasswordGenerator(){
    	super(MIN_CHARS, MAX_CHARS, USEDCHARS);
    }
      
}
