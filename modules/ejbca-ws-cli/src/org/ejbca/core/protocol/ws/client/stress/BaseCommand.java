package org.ejbca.core.protocol.ws.client.stress;

import org.ejbca.core.protocol.ws.client.CvcStressTestCommand;

public class BaseCommand {
    final protected JobData jobData;
    BaseCommand(JobData _jobData) {
        this.jobData = _jobData;
    }
    @Override
    public String toString() {
        return "Class \'" +this.getClass().getCanonicalName()+"' with this job data: "+ this.jobData.toString();
    }
}