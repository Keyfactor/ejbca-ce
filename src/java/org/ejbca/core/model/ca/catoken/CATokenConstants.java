package org.ejbca.core.model.ca.catoken;

public class CATokenConstants {

    public static final String SIGALG_SHA1_WITH_RSA            = "SHA1WithRSA";
    public static final String SIGALG_SHA256_WITH_RSA          = "SHA256WithRSA";
    public static final String SIGALG_MD5_WITH_RSA            = "MD5WithRSA";
    public static final String SIGALG_SHA1_WITH_ECDSA        = "SHA1withECDSA";   
    public static final String SIGALG_SHA256_WITH_ECDSA        = "SHA256withECDSA";   
    public static final String SIGALG_SHA256_WITH_RSA_AND_MGF1 = "SHA256WithRSAAndMGF1";
    public static final String SIGALG_SHA1_WITH_RSA_AND_MGF1 = "SHA1WithRSAAndMGF1"; // Not possible to select in Admin-GUI    
	/** This differs between java 1.5 and java 1.4 */    
    public static final String[] AVAILABLE_SIGALGS = {SIGALG_SHA1_WITH_RSA, SIGALG_SHA256_WITH_RSA, SIGALG_MD5_WITH_RSA, SIGALG_SHA256_WITH_RSA_AND_MGF1, SIGALG_SHA1_WITH_ECDSA, SIGALG_SHA256_WITH_ECDSA};
    
    public static final String KEYALGORITHM_RSA = "RSA";
    public static final String KEYALGORITHM_ECDSA = "ECDSA";

    public static final int CATOKENTYPE_P12          = 1;
    public static final int CATOKENTYPE_HSM          = 2;
	public static final int CATOKENTYPE_NULL         = 3;
	

}
