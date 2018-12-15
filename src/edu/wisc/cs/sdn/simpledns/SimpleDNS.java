package edu.wisc.cs.sdn.simpledns;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.concurrent.RecursiveAction;

import com.sun.org.apache.xerces.internal.impl.xpath.regex.RegularExpression;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdata;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataBytes;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class SimpleDNS 
{
	final static int LOCAL_DNS_PORT = 8053;
	final static int PORT_TO_SEND_DNS = 53;
	static int originalPort;
	static InetAddress originalIP;
	

	public static void main(String[] args) throws IOException
	{	
		if (args.length < 4) {
			System.err.println("Usage: java edu.wisc.cs.sdn.simpledns.SimpleDNS -r <IP adddress of root server> -e <EC2 instances csv>");
			System.exit(1);
		}

		String ip = null;
		String ec2Path = null;

		if (args[0].equals("-r")) {
			ip = args[1];
		} else if (args[0].equals("-e")) {
			ec2Path = args[1];
		}

		if (args[2].equals("-e")) {
			ec2Path = args[3];
		} else if (args[2].equals("-r")) {
			ip = args[3];
		}

		if (ip == null || ec2Path == null) {
			System.err.println("Usage: java edu.wisc.cs.sdn.simpledns.SimpleDNS -r <IP adddress of root server> -e <EC2 instances csv>");
			System.exit(1);
		}

		InetAddress rootIPAddr = getIPAddrObject(ip);
		if (rootIPAddr == null) {
			System.err.println("Cannot resolve root ip address");
			System.exit(1);
		}

		// Socket to process DNS request
		DatagramSocket sendSocket = new DatagramSocket();
		
		// Socket to listed for DNS request on port 8053
		DatagramSocket listenSocket = new DatagramSocket(LOCAL_DNS_PORT);
		DNS dnsRequest = listenForDig(listenSocket);
		
		System.out.println("root ip: " + ip + ", ec2Path: " + ec2Path);
		System.out.println("opcode: " + dnsRequest.getOpcode());
		HashSet<String> visitedNameServers = new HashSet<>();
		boolean recursionDesired = dnsRequest.isRecursionDesired(); 
		
		DNS resultPacket = null;
		try {
			resultPacket = process(sendSocket, dnsRequest, rootIPAddr, visitedNameServers, recursionDesired, 0);
		} catch (IOException e) {
			System.err.println("Unable to send the request out to port");
		}
		
		System.out.println("-------------------- Result packet ---------------------");
		System.out.println(resultPacket);
		System.out.println("--------------------------------------------------------");
		
		DatagramPacket finalResponse = null;
		InetAddress localHostAddr = getIPAddrObject("127.0.0.1");
		if (resultPacket != null) {
			finalResponse = constructDatagramPacketToSend(resultPacket, originalPort, originalIP);
		} else {
			
			// sending empty response if unable to resolve the domain name
			DNS dns = new DNS();
			dns.setId(dnsRequest.getId());
			finalResponse = constructDatagramPacketToSend(dns, originalPort, originalIP);
		}
		
		finalResponse.setAddress(originalIP);
		finalResponse.setPort(originalPort);

		// Send the result back to original localhost port 8503
		System.out.println("Sending the final packet back to IP: " + originalIP.getHostAddress() + ", port: " + originalPort);
		listenSocket.send(finalResponse);
		
	}
	
	public static void readEC2File(String path) {
		
	}
	
	public static boolean isValidQuery(DNS dnsRequest) {
		
		if (dnsRequest.getOpcode() != DNS.OPCODE_STANDARD_QUERY) {
			System.err.println("Not a standard opcode query");
			return false;
		}

		if (dnsRequest.getQuestions() == null || dnsRequest.getQuestions().size() == 0) {
			System.err.println("No query exists in this dns request");
			return false;
		}
		
		DNSQuestion ques = dnsRequest.getQuestions().get(0);
			
		if (DNS.TYPE_A != ques.getType() 
				&& DNS.TYPE_AAAA != ques.getType() 
				&& DNS.TYPE_CNAME != ques.getType()
				&& DNS.TYPE_NS != ques.getType()) {
			System.err.println("Query is not of type A, AAAA, CNAME or NS");
			return false;
		}
		
		return true;
	}
	
	public static DatagramPacket constructDatagramPacketToSend(DNS request, int port, InetAddress addr) {
		byte [] buf = request.serialize();
		return (new DatagramPacket(buf, buf.length, addr, PORT_TO_SEND_DNS));
	}
	
	public static DNS process(DatagramSocket sendSocket,  DNS request, InetAddress addrToSend, HashSet<String> visitedNameServers, boolean recurrsionDesired, int level) throws IOException {
		System.out.println("------------------------- Level " + level +  " -------------------------");
//		System.out.println("DNS request");
//		System.out.println(request);
		
		if (!isValidQuery(request)) {
			//System.out.println("Not a valid DNS request");
			return null;
		}
		
		// Always send the original request but change the addrs to
		DatagramPacket packetToSend = constructDatagramPacketToSend(request, PORT_TO_SEND_DNS, addrToSend);
		sendSocket.send(packetToSend);

		// Receiving the response for the request just sent
		byte[] recBuf = new byte[1500];
		DatagramPacket packet = new DatagramPacket(recBuf, recBuf.length);
		sendSocket.receive(packet);
		
		DNS result = DNS.deserialize(packet.getData(), packet.getData().length);
		
		if (result.getAnswers().size() > 0) {
			//System.out.println("Something found in answer section");
			return result; 
		}		
		
		// Send the result from the root NS back if recursion is not desired
		if (!recurrsionDesired) {
			System.out.println("Stopping here. Recursion is not desired");
			return result;
		}
		
		List<DNSResourceRecord> authority = result.getAuthorities();
		List<DNSResourceRecord> additional = result.getAdditional();
		List<DNSResourceRecord> skipped = new ArrayList<>();
		
		// Go over all the NS records in the 
		for (DNSResourceRecord record : authority) {
			if (record.getType() == DNS.TYPE_NS) {
				DNSResourceRecord matchedARecord = ifExistsInAuthority(record, additional, skipped);
								
				if (matchedARecord != null && !visitedNameServers.contains(matchedARecord.getName())) {
	
					// Ignore this to test the skipped servers
//					if (matchedARecord.getName().equals("ns-1497.awsdns-59.org")) {
//						continue;
//					}
					
					// Add the current NS to vistedNameServers
					visitedNameServers.add(matchedARecord.getName());
					
					// Find the ip of the name server and send the query to that name server
					String ip = matchedARecord.getData().toString();
					System.out.println("ip: " + ip);
					InetAddress addr = getIPAddrObject(ip);
					
					DNS newRequest = process(sendSocket, request, addr, visitedNameServers, recurrsionDesired, level + 1);
					if (newRequest != null) {
						return newRequest;
					}
				}
			}
		}
		
		// If some records were skipped
		for (DNSResourceRecord record : skipped) {
			// First request the A record for this NS 
			System.out.println("Checking skipped records now");
			System.out.println(record.getName());
			// the recursively call this function
		}
		
		return null;
	}
	
	public static DNSResourceRecord ifExistsInAuthority(DNSResourceRecord target, List<DNSResourceRecord> additional, List<DNSResourceRecord> skipped) {
		DNSRdata temp = target.getData();
		
		String targetStr = temp.toString();
		
		for (DNSResourceRecord record : additional) {
			System.out.println("targetStr: " + targetStr + ", addition: " + record.getName());
			
			// Checking if in the addition section either A or AAAA type of records exists
			if (targetStr.equals(record.getName()) && record.getType() == DNS.TYPE_A) {
				return record;
			}
			
			// Fix this
//			if (targetStr.equals(record.getName()) && record.getType() == DNS.TYPE_AAAA) {
//				return record;
//			}
		}
		skipped.add(target);
		return null;
	}
	
	
	public static void printDataInputStream(DataInputStream din) {
		try {
			System.out.println("Transaction ID: 0x" + String.format("%x", din.readShort()));
			System.out.println("Flags: 0x" + String.format("%x", din.readShort()));
			System.out.println("Questions: 0x" + String.format("%x", din.readShort()));
			System.out.println("Answers RRs: 0x" + String.format("%x", din.readShort()));
			System.out.println("Authority RRs: 0x" + String.format("%x", din.readShort()));
			System.out.println("Additional RRs: 0x" + String.format("%x", din.readShort()));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static DNS listenForDig(DatagramSocket listenSocket) {
		try {
			byte[] buf = new byte[1500];
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			listenSocket.receive(packet);

			originalPort = packet.getPort();
			originalIP = packet.getAddress();
			
			DNS dns = DNS.deserialize(packet.getData(), packet.getData().length);
			
			System.out.println("------------------ Original request -------------------");
			System.out.println(dns.toString());
			System.out.println("-------------------------------------------------------");
			
			return dns;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}


	public static InetAddress getIPAddrObject(String ip) {
		InetAddress rootIPAddr = null;
		byte [] addr = new byte[4];
		String [] subIP = ip.split("\\.");

		System.out.println("subIP: " + Arrays.toString(subIP) + ", length: " + subIP.length);

		for (int i = 0; i < 4; i++) {
			addr[i] = (byte)(Integer.parseInt(subIP[i]));
		}

		try {
			rootIPAddr = InetAddress.getByAddress(addr);
		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		}

		return rootIPAddr;
	}
}
