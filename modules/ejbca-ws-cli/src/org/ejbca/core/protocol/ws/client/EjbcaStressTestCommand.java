package org.ejbca.core.protocol.ws.client;

import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.stress.JobData;
import org.ejbca.core.protocol.ws.client.stress.CertificateRequestCommand;
import org.ejbca.core.protocol.ws.client.stress.EditUserCommand;
import org.ejbca.core.protocol.ws.client.stress.FindUserCommand;
import org.ejbca.core.protocol.ws.client.stress.ListCertsCommand;
import org.ejbca.core.protocol.ws.client.stress.MultipleCertsRequestsForAUserCommand;
import org.ejbca.core.protocol.ws.client.stress.Pkcs10RequestCommand;
import org.ejbca.core.protocol.ws.client.stress.RevokeCertBackdatedCommand;
import org.ejbca.core.protocol.ws.client.stress.RevokeCertCommand;
import org.ejbca.util.PerformanceTest;

import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

public class EjbcaStressTestCommand  extends StressTestCommandBase {

    public EjbcaStressTestCommand(String[] args) {
        super(args);
    }

    @Override
    protected void usage() {
        getPrintStream().println("Command used to perform a \"stress\" test of EJBCA.");
        getPrintStream().println("The command will start up a number of threads.");
        getPrintStream().println("Each thread will continuously add new users to EJBCA. After adding a new user the thread will fetch a certificate for it.");
        getPrintStream().println();
        getPrintStream().println("Usage : stress <caname> <nr of threads> <max wait time in ms to fetch cert after adding user> [<end entity profile name>] [<certificate profile name>] [<type of test>] [<nr of tests>]");
        getPrintStream().println();
        getPrintStream().println("Here is an example of how the test could be started:");
        getPrintStream().println("./ejbcaClientToolBox.sh EjbcaWsRaCli stress ManagementCA 20 5000");
        getPrintStream().println("20 threads is started. After adding a user the thread waits between 0-500 ms before requesting a certificate for it. The certificates will all be signed by the CA ManagementCA.");
        getPrintStream().println("You should use the CA with 'Enforce unique public keys' unchecked to avoid 'User ... is not allowed to use same key as another user is using.' error");
        getPrintStream().println();
        getPrintStream().println("To define a template for the subject DN of each new user use the java system property 'subjectDN'.");
        getPrintStream().println("If the property value contains one or several '<userName>' string these strings will be substituted with the user name.");
        getPrintStream().println("Example: JAVA_OPT=\"-DsubjectDN=CN=<userName>,O=Acme,UID=hej<userName>,OU=,OU=First Fixed,OU=sfsdf,OU=Middle Fixed,OU=fsfsd,OU=Last Fixed\" ./ejbcaClientToolBox.sh EjbcaWsRaCli stress ldapDirect 1 1000 ldapClientOUTest ldapClientDirect");
        getPrintStream().println();
        getPrintStream().println("To specify a key size, use the java system property 'keySize'.");
        getPrintStream().println("To specify a key algorithm, use the java system property 'keyAlgorithm'.  'RSA' and 'EC' are supported.");
        getPrintStream().println("To specify an EC curve, use the java system property 'curve'.  `keyAlgorithm` should be set to 'EC' when specifying a curve.");
        getPrintStream().println("Example: JAVA_OPT=\"-DkeyAlgorithm=EC -Dcurve=secp384r1\" ./ejbcaClientToolBox.sh EjbcaWsRaCli stress \"ManagementCA\" 50 10 EMPTY ENDUSER BASICSINGLETRANS");
        getPrintStream().println("         JAVA_OPT=\"-DkeySize=4096\" ./ejbcaClientToolBox.sh EjbcaWsRaCli stress \"ManagementCA\" 50 10 EMPTY ENDUSER BASICSINGLETRANS");
        getPrintStream().println();
        getPrintStream().print("Types of stress tests:");
        TestType testTypes[] = TestType.values();
        for ( TestType testType : testTypes ) {
            getPrintStream().print(" " + testType);
        }
        getPrintStream().println();
    }

    @Override
    protected PerformanceTest.CommandFactory getCommandFactory(String caName, String endEntityProfileName, String certificateProfileName, TestType testType, int maxCertificateSN, String subjectDN, String keyAlgorithm, int keySize, String curve) {
        return new EjbcaStressCommandFactory(caName, endEntityProfileName, certificateProfileName, testType, maxCertificateSN, subjectDN, keyAlgorithm, keySize, curve);
    }

    private class EjbcaStressCommandFactory implements PerformanceTest.CommandFactory {
        final private String caName;
        final private String endEntityProfileName;
        final private String certificateProfileName;
        final private TestType testType;
        final private int maxCertificateSN;
        final private String subjectDN;
        final private String keyAlgorithm;
        final private int keySize;
        final private String curve;

        EjbcaStressCommandFactory(String _caName, String _endEntityProfileName, String _certificateProfileName,
                                TestType _testType, int _maxCertificateSN, String _subjectDN,
                                String keyAlgorithm, int keySize, String curve ) {
            this.testType = _testType;
            this.caName = _caName;
            this.endEntityProfileName = _endEntityProfileName;
            this.certificateProfileName = _certificateProfileName;
            this.maxCertificateSN = _maxCertificateSN;
            this.subjectDN = _subjectDN;
            this.keyAlgorithm = keyAlgorithm;
            this.keySize = keySize;
            this.curve = curve;
        }

        @Override
        public PerformanceTest.Command[] getCommands() throws Exception {
            // create the key pair generator for P10 requests
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
            if (keyAlgorithm.equals("EC")) {
                kpg.initialize(new ECGenParameterSpec(curve));
            } else if (keyAlgorithm.equals("RSA")) {
                kpg.initialize(keySize);
            }

            final EjbcaWS ejbcaWS = getEjbcaRAWSFNewReference();
            final JobData jobData = new JobData(this.subjectDN, false);
            switch (this.testType) {
                case BASIC:
                    return new PerformanceTest.Command[]{
                            new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, true, this.maxCertificateSN, getLog()),
                            new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData, getLog()) };
                case BASICSINGLETRANS_SAMEUSER:
                case BASICSINGLETRANS:
                    boolean createNewUser = (testType == TestType.BASICSINGLETRANS);
                    boolean randomizeDn = (testType == TestType.BASICSINGLETRANS_SAMEUSER);
                    return new PerformanceTest.Command[]{
                            new CertificateRequestCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, createNewUser, randomizeDn, this.maxCertificateSN, kpg.generateKeyPair(), getLog())
                    };
                case REVOKE_BACKDATED:
                case REVOKE:
                    return new PerformanceTest.Command[]{
                            new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, true, this.maxCertificateSN, getLog()),
                            new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData, getLog()),
                            new FindUserCommand(ejbcaWS, jobData, getLog()),
                            new ListCertsCommand(ejbcaWS, jobData, getLog()),
                            this.testType.equals(TestType.REVOKE_BACKDATED) ? new RevokeCertBackdatedCommand(ejbcaWS, jobData, getLog()) : new RevokeCertCommand(ejbcaWS, jobData, getLog()),
                            new EditUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, false, -1, getLog()),
                            new Pkcs10RequestCommand(ejbcaWS, kpg.generateKeyPair(), jobData, getLog()) };
                case REVOKEALOT:
                    return new PerformanceTest.Command[]{
                            new MultipleCertsRequestsForAUserCommand(ejbcaWS, this.caName, this.endEntityProfileName, this.certificateProfileName, jobData, kpg, getLog()),
                            new FindUserCommand(ejbcaWS, jobData, getLog()),
                            new ListCertsCommand(ejbcaWS, jobData, getLog()),
                            new RevokeCertCommand(ejbcaWS, jobData, getLog())
                    };
                default:
                    return null;
            }
        }
    }
}
