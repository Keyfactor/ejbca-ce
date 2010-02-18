import java.io.*;
import java.net.URI;
import java.security.*;
import java.security.cert.*;
import java.util.*;

/**
 * Check the revocation status of a public key certificate using OCSP.
 */

public class ValidateCertUseOCSP {

    /*
     * Filename that contains the root CA cert of the OCSP server's cert.
     */
    private static final String ROOT_CA_CERT = "RootCA.pem";

    /*
     * Filename that contains the OCSP server's cert.
     */
    private static final String OCSP_SERVER_CERT = "OCSPServer.pem";

    /**
     * Checks the revocation status of a public key certificate using OCSP.
     *
     * Usage:  java ValidateCert <cert-file> [<OCSP-server>]
     *     <cert-file> is the filename of the certificate to be checked.
     *            The certificate must be in PEM format.
     *     <OCSP-server> is the URL of the OCSP server to use.
     *            If not supplied then the certificate must identify an OCSP
     *            server by means of its AuthorityInfoAccess extension.
     *            If supplied then it overrides any URL which may be present
     *            in the certificate's AuthorityInfoAccess extension.
     *
     * Example:  java \
     *             -Dhttp.proxyHost=proxy.example.net \
     *             -Dhttp.proxyPort=8080 \
     *             ValidateCert \
     *             mycert.pem \
     *             http://ocsp.openvalidation.org:80
     */
    public static void main(String[] args) {
	try {
	    CertPath cp = null;
	    Vector certs = new Vector();
	    URI ocspServer = null;

	    if (args.length == 0 || args.length > 2) {
		System.out.println(
		    "Usage: java ValidateCert <cert-file> [<OCSP-server>]");
		System.exit(-1);
	    }

	    // load the cert to be checked
	    certs.add(getCertFromFile(args[0]));

	    // handle location of OCSP server
	    if (args.length == 2) {
		ocspServer = new URI(args[1]);
	        System.out.println("Using the OCSP server at: " + args[1]);
	        System.out.println("to check the revocation status of: " +
		    certs.elementAt(0));
	        System.out.println();
	    } else {
	        System.out.println("Using the OCSP server specified in the " +
		    "cert to check the revocation status of: " +
		    certs.elementAt(0));
	        System.out.println();
	    }

	    // init cert path
	    CertificateFactory cf = CertificateFactory.getInstance("X509");
	    cp = (CertPath)cf.generateCertPath(certs);

	    // load the root CA cert for the OCSP server cert
	    X509Certificate rootCACert = getCertFromFile(ROOT_CA_CERT);

	    // init trusted certs
	    TrustAnchor ta = new TrustAnchor(rootCACert, null);
	    Set trustedCertsSet = new HashSet();
	    trustedCertsSet.add(ta);

	    // init cert store
	    Set certSet = new HashSet();
	    X509Certificate ocspCert = getCertFromFile(OCSP_SERVER_CERT);
	    certSet.add(ocspCert);
	    CertStoreParameters storeParams =
		new CollectionCertStoreParameters(certSet);
	    CertStore store = CertStore.getInstance("Collection", storeParams);

	    // init PKIX parameters
            PKIXParameters params = null;
	    params = new PKIXParameters(trustedCertsSet);
	    params.addCertStore(store);

	    // enable OCSP
	    Security.setProperty("ocsp.enable", "true");
	    if (ocspServer != null) {
		Security.setProperty("ocsp.responderURL", args[1]);
		Security.setProperty("ocsp.responderCertSubjectName",
		    ocspCert.getSubjectX500Principal().getName());
	    }

	    // perform validation
	    CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
	    PKIXCertPathValidatorResult cpv_result  =
		(PKIXCertPathValidatorResult) cpv.validate(cp, params);
	    X509Certificate trustedCert = (X509Certificate)
		cpv_result.getTrustAnchor().getTrustedCert();
	
	    if (trustedCert == null) {
		System.out.println("Trsuted Cert = NULL");
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
