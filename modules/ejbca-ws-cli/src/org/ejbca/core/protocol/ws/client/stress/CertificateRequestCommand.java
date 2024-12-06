package org.ejbca.core.protocol.ws.client.stress;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.core.protocol.ws.client.StressTestCommandBase;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.util.PerformanceTest;

import java.math.BigInteger;
import java.security.*;

public class CertificateRequestCommand extends BaseCommand implements PerformanceTest.Command {
    final private UserDataVOWS user;
    final private boolean doCreateNewUser;
    final private boolean randomizeDn;
    final private int bitsInCertificateSN;
    private PKCS10CertificationRequest pkcs10;

    public CertificateRequestCommand(
            EjbcaWS ejbcaWS,
            String caName,
            String endEntityProfileName,
            String certificateProfileName,
            JobData jobData,
            boolean doCreateNewUser,
            boolean randomizeDn,
            int bitsInCertificateSN,
            KeyPair keys,
            PerformanceTest.Log log
    ) throws SignatureException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        super(ejbcaWS, jobData, log);
        this.doCreateNewUser = doCreateNewUser;
        this.randomizeDn = randomizeDn;
        this.user = new UserDataVOWS();
        this.user.setClearPwd(true);
        this.user.setCaName(caName);
        this.user.setEmail(null);
        this.user.setSubjectAltName(null);
        this.user.setStatus(EndEntityConstants.STATUS_NEW);
        this.user.setTokenType(org.ejbca.core.protocol.ws.objects.UserDataVOWS.TOKEN_TYPE_USERGENERATED);
        this.user.setEndEntityProfileName(endEntityProfileName);
        this.user.setCertificateProfileName(certificateProfileName);
        this.bitsInCertificateSN = bitsInCertificateSN;
        if (!doCreateNewUser) {
            this.jobData.passWord = "foo123";
            this.jobData.userName = "WSTESTUSER_REUSE_"+ StressTestCommandBase.nextLong();
        }
        String signAlgorithm = "SHA256WithRSA";
        if (keys.getPublic().getAlgorithm().equals("ECDSA")) {
            signAlgorithm = "SHA256withECDSA";
        } else if(keys.getPublic().getAlgorithm().equalsIgnoreCase("Ed25519")) {
            signAlgorithm = "ed25519";
        } else if(keys.getPublic().getAlgorithm().equalsIgnoreCase("Ed448")) {
            signAlgorithm = "ed448";
        }
        try {
            this.pkcs10 = CertTools.genPKCS10CertificationRequest(
                    signAlgorithm,
                    DnComponents.stringToBcX500Name("CN=NOUSED"), keys.getPublic(), new DERSet(), keys.getPrivate(), null);
        } catch (OperatorCreationException e) {
            StressTestCommandBase.getPrintStream().println(e.getLocalizedMessage());
            e.printStackTrace(StressTestCommandBase.getPrintStream());
        }
    }

    @Override
    public boolean doIt() throws Exception {
        if ( this.doCreateNewUser ) {
            this.jobData.passWord = "foo123";
            this.jobData.userName = "WSTESTUSER"+ StressTestCommandBase.nextLong();
        }
        if ( this.bitsInCertificateSN>0 && this.doCreateNewUser ) {
            this.user.setCertificateSerialNumber(new BigInteger(this.bitsInCertificateSN, StressTestCommandBase.getRandom()));
        }
        if (randomizeDn) {
            this.user.setSubjectDN(this.jobData.getDN() + "_" + StressTestCommandBase.nextLong());
        } else {
            this.user.setSubjectDN(this.jobData.getDN());
        }
        this.user.setUsername(this.jobData.userName);
        this.user.setPassword(this.jobData.passWord);
        int requestType = org.ejbca.core.protocol.ws.common.CertificateHelper.CERT_REQ_TYPE_PKCS10;
        String responseType = org.ejbca.core.protocol.ws.common.CertificateHelper.RESPONSETYPE_CERTIFICATE;
        String requestData = new String(Base64.encode(this.pkcs10.getEncoded()));
        final CertificateResponse certificateResponse = this.ejbcaWS.certificateRequest(this.user, requestData, requestType, null, responseType);
        return checkAndLogCertificateResponse(certificateResponse, this.jobData, !randomizeDn);
    }

    @Override
    public String getJobTimeDescription() {
        if ( this.doCreateNewUser ) {
            return "Relative time spent registering new users";
        }
        return "Relative time spent setting status of user to NEW";
    }
}
