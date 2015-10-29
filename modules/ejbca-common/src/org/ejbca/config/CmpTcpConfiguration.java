package org.ejbca.config;

public class CmpTcpConfiguration {
    
    public static int getTCPPortNumber() {
        return Integer.valueOf(EjbcaConfigurationHolder.getString("cmp.tcp.portno"));
    }
    
    public static String getTCPLogDir() {
        return EjbcaConfigurationHolder.getString("cmp.tcp.logdir");
    }
    
    public static String getTCPConfigFile() {
        return EjbcaConfigurationHolder.getString("cmp.tcp.conffile");
    }
    
    public static String getTCPBindAdress() {
        return EjbcaConfigurationHolder.getString("cmp.tcp.bindadress");
    }
}