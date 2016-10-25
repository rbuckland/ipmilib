/*
 * MessageQueue.java 
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
import com.veraxsystems.vxipmi.common.PropertiesManager;
import com.veraxsystems.vxipmi.connection.Connection;
import com.veraxsystems.vxipmi.connection.ConnectionException;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimerTask;
import java.util.concurrent.ScheduledFuture;

/**
 * Queues messages to send and checks for timeouts.
 */
public class MessageQueue implements Runnable {

	private final ScheduledFuture<?> timerTask;
	private final List<QueueElement> queue;
	private int timeout;
	private Connection connection;
	private int lastSequenceNumber;
	private final Object lastSequenceNumberLock = new Object();

	private static Logger logger = Logger.getLogger(MessageQueue.class);

	/**
	 * Frequency of checking messages for timeouts in ms.
	 */
	private static int cleaningFrequency = 500;

	/**
	 * Size of the queue determined by IPMI sliding window algorithm
	 * specification. <br>
	 * When queue size is 16, BMC drops some of the messages under heavy load.
	 */
	private static final int QUEUE_SIZE = 8;

	public int getTimeout() {
		return timeout;
	}

	public void setTimeout(int timeout) {
		this.timeout = timeout;
	}

    public MessageQueue(Connection connection, int timeout) throws IOException {
        if (cleaningFrequency == -1) {
            cleaningFrequency = Integer.parseInt(PropertiesManager.getInstance().getProperty("cleaningFrequency"));
        }
        reservedTags = new ArrayList<Integer>();
        lastSequenceNumber = 0;
        this.connection = connection;
        queue = new ArrayList<QueueElement>();
        setTimeout(timeout);
        timerTask = connection.startTimer(this, cleaningFrequency);
	}

	/**
	 * Stops the MessageQueue
	 */
	public void tearDown() {
		this.timerTask.cancel(true);
	}

	private List<Integer> reservedTags;

	/**
	 * Check if the tag is reserved.
	 */
	private synchronized boolean isReserved(int tag) {
		return reservedTags.contains(tag);
	}

	/**
	 * Reserves given tag for the use of the invoker.
	 * 
	 * @param tag
	 *            - tag to reserve
	 * @return true if tag was reserved successfully, false otherwise
	 */
	private synchronized boolean reserveTag(int tag) {
		if (isReserved(tag)) {
			reservedTags.add(tag);
			return true;
		}
		return false;
	}

	private synchronized void releaseTag(int tag) {
		reservedTags.remove((Integer) tag);
	}

	/**
	 * Adds request to the queue and generates the tag.
	 * 
	 * @return Session sequence number of the message if it was added to the
	 *         queue, -1 otherwise. The tag used to identify message is equal to
	 *         that value % 64.
	 */
	public int add(IpmiCommandCoder request) {
		run();
		boolean first = true;
		synchronized (queue) {
			synchronized (lastSequenceNumberLock) {
				if (queue.size() < QUEUE_SIZE) {
					int sequenceNumber = (lastSequenceNumber + 1)
							% (Integer.MAX_VALUE / 4);

					if (sequenceNumber == 0) {
						throw new ArithmeticException(
								"Session sequence number overload. Reset session");
					}

					while (isReserved(sequenceNumber % 64)) {
						sequenceNumber = (sequenceNumber + 1)
								% (Integer.MAX_VALUE / 4);

						if (!first) {
							try {
								Thread.sleep(1);
							} catch (InterruptedException e) {
								// TODO log
							}
						}

						if (sequenceNumber == 0) {
							throw new ArithmeticException(
									"Session sequence number overload. Reset session");
						}
						first = false;
					}

					reserveTag(sequenceNumber % 64);

					lastSequenceNumber = sequenceNumber;

					QueueElement element = new QueueElement(sequenceNumber,
							request);

					queue.add(element);
					return sequenceNumber;
				}
			}
		}
		return -1;

	}

	/**
	 * Removes message with the given tag from the queue.
	 */
	public void remove(int tag) {
		run();
		synchronized (queue) {
			int i = 0;
			int index = -1;
			for (QueueElement element : queue) {
				if (element.getId() % 64 == tag) {
					index = i;
					break;
				}
				++i;
			}
			if (index == 0) {
				queue.remove(0);
				releaseTag(tag);
				while (queue.size() > 0 && queue.get(0).getRequest() == null) {
					int additionalTag = queue.get(0).getId() % 64;
					queue.remove(0);
					releaseTag(additionalTag);
				}
			} else if (index > 0) {
				queue.get(index).setRequest(null);
			}

		}
	}

	/**
	 * Returns valid session sequence number that cannot be used as a tag though
	 */
	public int getSequenceNumber() {
		synchronized (lastSequenceNumberLock) {
			int sequenceNumber = (lastSequenceNumber + 1)
					% (Integer.MAX_VALUE / 4);

			if (sequenceNumber == 0) {
				throw new ArithmeticException(
						"Session sequence number overload. Reset session");
			}
			lastSequenceNumber = sequenceNumber;
			return sequenceNumber;
		}
	}

	/**
	 * Returns message with the given sequence number from the queue or null if
	 * no message with the given tag is currently in the queue.
	 */
	public IpmiCommandCoder getMessageFromQueue(int tag) {
		synchronized (queue) {
			for (QueueElement element : queue) {
				if (element.getId() % 64 == tag && element.getRequest() != null) {
					return element.getRequest();
				}
			}
		}
		return null;
	}

	/**
	 * {@link TimerTask} runner - periodically checks queue for timed out
	 * messages.
	 */
	@Override
	public void run() {
		if (queue != null) {
			synchronized (queue) {
				boolean process = true;
				while (process && queue.size() > 0) {
					Date now = new Date();
					if (now.getTime() - queue.get(0).getTimestamp().getTime() > (long) timeout
							|| queue.get(0).getRequest() == null) {
						int tag = queue.get(0).getId() % 64;
						boolean done = queue.get(0).getRequest() == null;
						queue.remove(0);
						logger.info("Removing message after timeout, tag: "
								+ tag);
						releaseTag(tag);
						if (!done) {
							connection.notifyListeners(connection.getHandle(),
									tag, null, new ConnectionException(
											"Message timed out"));
						}
					} else {
						process = false;
					}
				}
			}
		}
	}
}
