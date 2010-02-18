import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Check the revocation status of a public key certificate using a CRL.
 *
 * NOTE: it only works with V1 CRLs
 */

public class ValidateCertUseCRL {

    /*
     * Filename that contains the root CA cert 
     */
    private static final String ROOT_CA_CERT = "DemoCA.pem";

    /**
     * Checks the revocation status of a public key certificate using CRL.
     *
     * Usage:  java ValidateCertUseCRL <cert-file> [<CRL-location>]
     *     <cert-file> is the filename of the certificate to be checked.
     *             The certificate must be in PEM format.
     *     <CRL> is the URL of the CRL to use.
     *             If not supplied then the certificate must identify the CRL
     *             by means of its CRL Distribution Points extension.
     *             If supplied then it overrides any URL which may be present
     *             in the certificate's CRLDP extension.
     *
     * Example:  java \
     *             -Dhttp.proxyHost=webcache.sfbay.sun.com \
     *             -Dhttp.proxyPort=8080 \
     *             ValidateCertUseCRL \
     *             mycert.pem \
     *             http://www.sun.com/pki/pkirootca.crl
     */
    public static void main(String[] args) {
	try {
	    CertPath cp = null;
	    Vector<X509Certificate> certs = new Vector<X509Certificate>();
	    URL url = null;

	    if (args.length == 0 || args.length > 2) {
		System.out.println(
		    "Usage: java ValidateCertUseCRL <cert-file> [<CRL-location>]");
		System.exit(-1);
	    }

	    // load the cert to be checked
	    certs.add(getCertFromFile(args[0]));

	    // handle location of CRL
	    if (args.length == 2) {
		url = new URL(args[1]);
	        System.out.println("Using the CRL at: " + args[1]);
	        System.out.println("to check the revocation status of: " +
		    certs.elementAt(0));
	        System.out.println();
	    } else {
	        System.out.println("Using the CRL specified in the " +
		    "cert to check the revocation status of: " +
		    certs.elementAt(0));
	        System.out.println();
		System.setProperty("com.sun.security.enableCRLDP", "true");
	    }

	    // init cert path
	    CertificateFactory cf = CertificateFactory.getInstance("X509");
	    cp = (CertPath)cf.generateCertPath(certs);

	    // load the root CA cert 
	    X509Certificate rootCACert = getCertFromFile(ROOT_CA_CERT);

	    // init trusted certs
	    TrustAnchor ta = new TrustAnchor(rootCACert, null);
	    Set<TrustAnchor> trustedCerts = new HashSet<TrustAnchor>();
	    trustedCerts.add(ta);

	    // init PKIX parameters
            PKIXParameters params = new PKIXParameters(trustedCerts);

	    // load the CRL
	    if (url != null) {
		URLConnection connection = url.openConnection();
		connection.setDoInput(true);
		connection.setUseCaches(false);
		DataInputStream inStream =
		    new DataInputStream(connection.getInputStream());
		X509CRL crl = (X509CRL)cf.generateCRL(inStream);
		inStream.close();
	        params.addCertStore(CertStore.getInstance("Collection",
		    new CollectionCertStoreParameters(
			Collections.singletonList(crl))));
	    }

	    // perform validation
	    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
	    PKIXCertPathValidatorResult cpv_result  =
		(PKIXCertPathValidatorResult) cpv.validate(cp, params);
	    X509Certificate trustedCert = (X509Certificate)
		cpv_result.getTrustAnchor().getTrustedCert();
	    
	    if (trustedCert == null) {
		System.out.println("Trusted Cert = NULL");
	    } else {
		System.out.println("Trusted CA DN = " +
		    trustedCert.getSubjectDN());
	    }
	    
	} catch (CertPathValidatorException e) {
	    e.printStackTrace();
	    System.exit(1);

	} catch(Exception e) {
	    e.printStackTrace();
	    System.exit(-1);
	}
	System.out.println("CERTIFICATE VALIDATION SUCCEEDED");
	System.exit(0);
    }

    /*
     * Read a certificate from the specified filepath.
     */
    private static X509Certificate getCertFromFile(String path) {
        X509Certificate cert = null;
        try {

            File certFile = new File(path);
            if (!certFile.canRead()) {
                throw new IOException(" File " + certFile.toString() + " is unreadable");
            }
            FileInputStream fis = new FileInputStream(path);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            cert = (X509Certificate)cf.generateCertificate(fis);

        } catch(Exception e) {
        	System.out.println("Can't construct X509 Certificate. " + e.getMessage());
        }
        return cert;
    }
}
