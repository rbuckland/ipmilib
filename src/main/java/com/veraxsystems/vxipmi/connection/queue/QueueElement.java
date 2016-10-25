/*
 * QueueElement.java 
 * Created on 2011-08-24
 *
 * Copyright (c) Verax Systems 2011.
 * All rights reserved.
 *
 * This software is furnished under a license. Use, duplication,
 * disclosure and all other uses are restricted to the rights
 * specified in the written license agreement.
 */
package com.veraxsystems.vxipmi.connection.queue;

import com.veraxsystems.vxipmi.coding.commands.IpmiCommandCoder;
import com.veraxsystems.vxipmi.coding.commands.ResponseData;

import java.util.Date;

public class QueueElement {
	private int id;

	private IpmiCommandCoder request;
	private ResponseData response;
	private Date timestamp;

	public QueueElement(int id, IpmiCommandCoder request) {
		this.id = id;
		this.request = request;
		timestamp = new Date();
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}
	
	public IpmiCommandCoder getRequest() {
		return request;
	}

	public void setRequest(IpmiCommandCoder request) {
		this.request = request;
	}

	public ResponseData getResponse() {
		return response;
	}

	public void setResponse(ResponseData response) {
		this.response = response;
	}
	
	public Date getTimestamp() {
		return timestamp;
	}
}
