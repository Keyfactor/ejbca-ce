The javax.xml.soap.MetaFactory file under services is there to specify that the Sun-RI SAAJ implementation
should be used. If running on for example JBoss 4.2.0 without this file, it will try to use a JBoss
implementation of the SAAJ factory, and an error occurs.
