package se.anatom.ejbca.util;

import java.util.*;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.rmi.PortableRemoteObject;

import org.apache.log4j.BasicConfigurator;
import org.apache.log4j.Logger;

import se.anatom.ejbca.IJobRunnerSessionHome;
import se.anatom.ejbca.log.Admin;


/**
 * JobRunner is used to run jobs implementing the IJobRunnerSession interface. The following
 * information has to be supplied on the command line: - provider    (url for the server, ex.
 * jnp://127.0.0.1:1099) - principal   (the user name is needed) - credentials (the password is
 * needed) - agent       (the JNDI-name of the agent session to start)
 *
 * @version $Id: JobRunner.java,v 1.7 2003-09-04 09:33:53 herrvendil Exp $
 */
public class JobRunner extends java.lang.Object {
    private static Logger log = Logger.getLogger(JobRunner.class);
    private static final String JNDI_PROVIDER = "java.naming.provider.url";
    private static final String JNDI_PRINCIPAL = "java.naming.security.principal";
    private static final String JNDI_CREDENTIALS = "java.naming.security.credentials";
    private InitialContext context;

    /**
     * Constructor
     *
     * @param props properties for creating initial context
     */
    public JobRunner(Properties props) throws NamingException {
        context = new InitialContext(props);
    }

    /**
     * Constructor
     */
    public JobRunner() throws NamingException {
        context = new InitialContext();
    }

    /**
     * Runs job
     *
     * @param jndiName jndi name of agent
     */

    private void runJob(String jndiName, String issuerdn) throws Exception {
        IJobRunnerSessionHome home  = (IJobRunnerSessionHome)PortableRemoteObject.narrow( context.lookup(jndiName) , 
IJobRunnerSessionHome.class );
        home.create().run(new Admin(Admin.TYPE_INTERNALUSER), issuerdn);

    }

    /**
     * Main for running jobs from the command line.
     *
     * @param args see class description
     */
    public static void main( String[] args ) {
        String issuerdn = null;
        BasicConfigurator.configure();

        if ( (args.length != 5) && (args.length != 2) ){
            log.error( "Usage: JobRunner <providerurl> <username> <password> <jndiname>  <issuerdn>" );
            log.error( "Usage: JobRunner <jndiname> <issuerdn>" );
            return;
        }

        JobRunner runner = null;
        String job = null;

        try {
            if (args.length == 4) {
                String provider = args[0];
                String principal = args[1];
                String credentials = args[2];
                job = args[3];
                issuerdn = args[4];

                Properties props = new Properties();
                props.setProperty(JNDI_PROVIDER, provider);
                props.setProperty(JNDI_PRINCIPAL, principal);
                props.setProperty(JNDI_CREDENTIALS, credentials);
                runner = new JobRunner(props);
            } else {
                job = args[0];
                issuerdn = args[1];
                runner = new JobRunner();
            }

            if (job != null) {
                runner.runJob(job, issuerdn);
            }
        } catch (Exception e) {
            log.error("Error running job " + job, e);
        }
    }
}
