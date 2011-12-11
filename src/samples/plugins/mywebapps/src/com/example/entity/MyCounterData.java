package com.example.entity;

import java.io.Serializable;

import org.apache.log4j.Logger;

import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Column;  
import javax.persistence.Id;
import javax.persistence.EntityManager;
import javax.persistence.Query;


@Entity
@Table(name = "MyCounterData")
public class MyCounterData implements Serializable {

    private static final long serialVersionUID = -8493105317760641442L;

    private static final Logger log = Logger.getLogger(MyCounterData.class);
    
    private int pk;
    private int counter;
    
    public void setPk (int pk) { this.pk = pk; }
	public int getPk () { return pk; }
	
    public void setCounter (int counter) { this.counter = counter; }
	public int getCounter () { return counter; }

}
