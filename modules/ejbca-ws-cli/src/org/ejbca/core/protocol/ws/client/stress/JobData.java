package org.ejbca.core.protocol.ws.client.stress;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.ejbca.core.protocol.ws.client.StressTestCommandBase.USER_NAME_TAG;

public class JobData {
    final boolean forCvc;
    public String userName;
    public String passWord;
    final String subjectDN;
    Certificate userCertsToBeRevoked[];
    List<X509Certificate> userCertsGenerated = new ArrayList<>();
    public JobData(String subjectDN, boolean forCvc) {
        this.subjectDN = subjectDN;
        this.forCvc = forCvc;
    }
    public String getDN() {
        String usernameAsDn = this.subjectDN.replace(USER_NAME_TAG, this.userName);
        if (forCvc && !usernameAsDn.contains("C=")) {usernameAsDn = usernameAsDn + ",C=SE";}
        return usernameAsDn;
    }
    @Override
    public String toString() {
        return "Username '"+this.userName+"' with password '"+this.passWord+"'.";
    }
}
