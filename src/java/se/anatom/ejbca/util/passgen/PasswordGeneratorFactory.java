package se.anatom.ejbca.util.passgen;

/**
 * Factory class creating PasswordGenerators.
 *
 * @version $Id: PasswordGeneratorFactory.java,v 1.1 2003-10-21 13:48:47 herrvendil Exp $
 */
public class PasswordGeneratorFactory {
    
    public static final int PASSWORDTYPE_4DIGITS                          = 0;
    public static final int PASSWORDTYPE_6TO8DIGITS                    = 1;
    public static final int PASSWORDTYPE_6TO8LETTERSANDDIGITS = 2;
	public static final int PASSWORDTYPE_6TO8ALLPRINTABLE         = 3;	
    
    static final IPasswordGenerator[] classes = { new Digit4CharPasswordGenerator(), 
    	                                                                  new DigitPasswordGenerator(),
    	                                                                  new LettersAndDigitsPasswordGenerator(),
    	                                                                  new AllPrintableCharPasswordGenerator()};
   
    
    /**
     *  Method returning an instance of the specified IPasswordGenerator class.
     *      
     *  @param type should be on of the PasswordGeneratorFactory constants.
     */
    
    public static IPasswordGenerator getInstance(int type){
       return classes[type];	    	
    }
   
}
