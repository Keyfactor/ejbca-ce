package org.ejbca.core.protocol.ws.client.stress;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.ejbca.core.protocol.ws.client.StressTestCommandBase.USER_NAME_TAG;

public class JobData {
    public String userName;
    public String passWord;
    final String subjectDN;
    X509Certificate userCertsToBeRevoked[];
    List<X509Certificate> userCertsGenerated = new ArrayList<>();
    public JobData(String subjectDN) {
        this.subjectDN = subjectDN;
    }
    public String getDN() {
        return this.subjectDN.replace(USER_NAME_TAG, this.userName);
    }
    @Override
    public String toString() {
        return "Username '"+this.userName+"' with password '"+this.passWord+"'.";
    }
}
