package se.anatom.ejbca.util.passgen;

/**
 * Factory class creating PasswordGenerators.
 *
 * @version $Id: PasswordGeneratorFactory.java,v 1.2 2003-12-05 14:49:10 herrvendil Exp $
 */
public class PasswordGeneratorFactory {
    
    
    public static final int PASSWORDTYPE_DIGITS                       = 0;
    public static final int PASSWORDTYPE_LETTERSANDDIGITS             = 1;
	public static final int PASSWORDTYPE_ALLPRINTABLE                 = 2;	
    
    static final IPasswordGenerator[] classes = { new DigitPasswordGenerator(),
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
