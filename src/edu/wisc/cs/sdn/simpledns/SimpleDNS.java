package edu.wisc.cs.sdn.simpledns;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;

import edu.wisc.cs.sdn.simpledns.packet.DNS;
import edu.wisc.cs.sdn.simpledns.packet.DNSQuestion;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdata;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataBytes;
import edu.wisc.cs.sdn.simpledns.packet.DNSRdataString;
import edu.wisc.cs.sdn.simpledns.packet.DNSResourceRecord;

public class SimpleDNS 
{
	final static int LOCAL_DNS_PORT = 8053;
	final static int PORT_TO_SEND_DNS = 53;
	static int originalPort;
	static InetAddress originalIP;
	static InetAddress rootIPAddr;
	static DNS originalDNS;
	static short originalType;

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

		rootIPAddr = getIPAddrObject(ip);
		if (rootIPAddr == null) {
			System.err.println("Cannot resolve root ip address");
			System.exit(1);
		}

		// Socket to process DNS request
		DatagramSocket sendSocket = new DatagramSocket();
		
		// Socket to listed for DNS request on port 8053
		DatagramSocket listenSocket = new DatagramSocket(LOCAL_DNS_PORT);
		DNS dnsRequest = listenForDig(listenSocket);
		
		//System.out.println("Original DNS request");
		//System.out.println(dnsRequest);
		originalDNS = dnsRequest;
		originalType = dnsRequest.getQuestions().get(0).getType();
		
		//System.out.println("root ip: " + ip + ", ec2Path: " + ec2Path);
		//System.out.println("opcode: " + dnsRequest.getOpcode());
		HashSet<String> visitedNameServers = new HashSet<>();
		boolean recursionDesired = dnsRequest.isRecursionDesired(); 
		
		DNS resultPacket = null;
		try {
			resultPacket = process(sendSocket, dnsRequest, rootIPAddr, visitedNameServers, recursionDesired, 0);
		} catch (IOException e) {
			System.err.println("Error: Unable to send the request out to port");
			e.printStackTrace();
		}
		
		System.out.println("-------------------- Result packet before resolving CNAME ---------------------");
		System.out.println(resultPacket);
		System.out.println("--------------------------------------------------------");
		
		DatagramPacket finalResponse = null;
		
		if (resultPacket != null) {
			
			// Check for CNAME
			if (originalType == DNS.TYPE_A || originalType == DNS.TYPE_AAAA) {
				resultPacket = resolveIfCNAMEExists(resultPacket, sendSocket);	
			}
			
			// Check for EC2 regions
			if (originalType == DNS.TYPE_A) {
				int oaLength = resultPacket.getAnswers().size(); 
				resultPacket = readEC2File(ec2Path, resultPacket);
				System.out.println("============= Result packet after resolving EC2 server ================");
				System.out.println(resultPacket.toString());
				System.out.println("=======================================================================");
				int naLength = resultPacket.getAnswers().size();
				System.out.println("Old ans length: " + oaLength + ", new ans length: " + naLength);
			}
			
			System.out.println(resultPacket.getAnswers().size());
			
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
	
	public static DatagramPacket constructDatagramPacketToSend(DNS request, int port, InetAddress addr) {
		byte [] buf = request.serialize();
		return (new DatagramPacket(buf, buf.length, addr, PORT_TO_SEND_DNS));
	}
	
	public static DNS process(DatagramSocket sendSocket,  DNS request, InetAddress addrToSend, HashSet<String> visitedNameServers, boolean recursionDesired, int level) throws IOException {
		System.out.println("------------------------- Level " + level +  " DNS Request-------------------------");
		System.out.println(request);
		System.out.println("---------------------------------------------------------------------------------");
//		
		if (!isValidQuery(request)) {
			//System.out.println("Not a valid DNS request");
			return null;
		}
		
		// Always send the original request but change the addrs to
		System.out.println("Sending request to " + addrToSend.getHostName() + ", " + addrToSend.getHostAddress());
		// Receiving the response for the request just sent
		byte[] recBuf = new byte[1500];
		DatagramPacket packet = new DatagramPacket(recBuf, recBuf.length);
		DatagramPacket packetToSend = constructDatagramPacketToSend(request, PORT_TO_SEND_DNS, addrToSend);
		
		
		sendSocket.send(packetToSend);
		sendSocket.receive(packet);
		
		DNS result = DNS.deserialize(packet.getData(), packet.getData().length);
		
		System.out.println("Successfuly deserialized");
		
		if (result.getAnswers().size() > 0) {
			////System.out.println("Something found in answer section");
			return result; 
		}		
		
		System.out.println("Result");
		System.out.println(result);
		System.out.println("Answers not found");
		
		// Send the result from the root NS back if recursion is not desired
		if (!recursionDesired) {
			System.out.println("Stopping here. Recursion is not desired");
			return result;
		}
		
		//System.out.println("recursion is desired");
		
		List<DNSResourceRecord> authority = result.getAuthorities();
		List<DNSResourceRecord> additional = result.getAdditional();
		List<DNSResourceRecord> skipped = new ArrayList<>();
		
		// Go over all the NS records in the 
		for (DNSResourceRecord record : authority) {
			if (record.getType() == DNS.TYPE_NS) {
				DNSResourceRecord matchedARecord = ifExistsInAdditional(record, additional, skipped);
							
				if (matchedARecord != null && !visitedNameServers.contains(matchedARecord.getName())) {
	
					// Ignore this to test the skipped servers
//					if (matchedARecord.getName().equals("ns-1497.awsdns-59.org")) {
//						continue;
//					}
					
					System.out.println("Sending request to name server: " +  matchedARecord.getName());
					System.out.println("matchedARecord");
					System.out.println(matchedARecord);
					
					// Add the current NS to vistedNameServers
					visitedNameServers.add(matchedARecord.getName());
					
					// Find the ip of the name server and send the query to that name server
					String ip = matchedARecord.getData().toString();
					System.out.println("ip: " + ip);
					
					InetAddress addr = getIPAddrObject(ip);
					
					DNS newRequest = process(sendSocket, request, addr, visitedNameServers, recursionDesired, level + 1);
					if (newRequest != null) {
						return newRequest;
					}
				}
			}
		}
		
		
		System.out.println("Done with all authority section records at level: " + level);
				
		System.out.println("Trying to find A records for skipped NS");
		
		System.out.println(skipped.toString());
		
		// If some records were skipped
		for (DNSResourceRecord record : skipped) {
			// First request the A record for this NS 
			//System.out.println("Checking skipped records now");
			
			
			
			//System.out.println(record.getData().toString());
			
			InetAddress resolveIPAddr = resolveARecordForNS(record, rootIPAddr, sendSocket);
			
			if (resolveIPAddr != null) {
				System.out.println("Resolved IP address: " + resolveIPAddr.getHostAddress() + ", " + resolveIPAddr.getHostName());
				DNS newRequest = process(sendSocket, request, resolveIPAddr, visitedNameServers, recursionDesired, level + 1);
				
				if (newRequest != null) {
					return newRequest;
				}
			}
			
			// the recursively call this function
		}
		
		System.out.println("Done resolving name servers at this level. Going a level below.");
		
		return null;
	}
	
	
	public static DNS resolveIfCNAMEExists(DNS resultPacket, DatagramSocket sendSocket) throws IOException {
		System.out.println("########################## Inside resolveIfCNAMEExists ###################################");
		System.out.println("##########################################################################################");
		System.out.println("##########################################################################################");
		System.out.println("##########################################################################################");
		System.out.println("##########################################################################################");
		System.out.println("##########################################################################################");
		
		
		if (isARecordPresent(resultPacket)) {
			return resultPacket;
		}
		
		List<DNSResourceRecord> answers = new ArrayList<>(resultPacket.getAnswers());
				
		for (DNSResourceRecord ans : answers) {
			
			System.out.println("CNAME record exists. Need to resolve it " + ans.toString());
			
			if (ans.getType() == DNS.TYPE_CNAME) {
				
				DNSQuestion oQues = originalDNS.getQuestions().get(0);
				originalDNS.removeQuestion(oQues);
				
				DNSQuestion newQues = new DNSQuestion(ans.getData().toString(), DNS.TYPE_A);
				originalDNS.addQuestion(newQues);
				
				HashSet<String> visitedNameServers = new HashSet<>();
				boolean recursionDesired = true;
				
				DNS result = process(sendSocket, originalDNS, rootIPAddr, visitedNameServers, recursionDesired, 0);
				
				System.out.println("Result inside CNAME resolution is");
				System.out.println(result.toString());
				
				
				if (result != null) {
					result = resolveIfCNAMEExists(result, sendSocket);
				}
				
				List<DNSResourceRecord> newAnswers = result.getAnswers();
				for (DNSResourceRecord newAns : newAnswers) {
					resultPacket.addAnswer(newAns);
				}
				
				// Fix the DNS request
				originalDNS.removeQuestion(newQues);
				originalDNS.addQuestion(oQues);
				
			}
		}
		System.out.println("#########################################################################");
		return resultPacket;
	}
	
	public static boolean isARecordPresent(DNS resultPacket) {
		List<DNSResourceRecord> answers = resultPacket.getAnswers();
		for (DNSResourceRecord ans : answers) {
			if (ans.getType() == DNS.TYPE_A) {
				return true;
			}
		}
		return false;
	}
	
	
	public static DNS readEC2File(String path, DNS resultPacket) {
		
		System.out.println("Inside read EC2");
		List<DNSResourceRecord> answers = new ArrayList<>(resultPacket.getAnswers());
		List<DNSResourceRecord> txtAnswers = new ArrayList<>();
		int count = 0;
		
		try {
			Scanner scanner = new Scanner(new File(path));
			while (scanner.hasNextLine()) {
				String [] currServer = scanner.nextLine().split(",");
				String [] ipAndMask = currServer[0].split("/");
				System.out.println("currServer: " + Arrays.toString(currServer) + ", ipAndMask: " + Arrays.toString(ipAndMask));
				checkIfEC2(answers, txtAnswers, ipAndMask, currServer[1]);
				System.out.println("----------------------------------------------------------------------------------------------");
				count++;
			}
			
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Size of TXT answers is " + txtAnswers.size());
		
		for (DNSResourceRecord txtRecord : txtAnswers) {
			System.out.println("Adding text records");
			System.out.println(txtRecord.toString());
			resultPacket.addAnswer(txtRecord);
		}
		
		System.out.println("Done with read EC2");
		return resultPacket;
	}
	
	public static boolean checkIfEC2(List<DNSResourceRecord> answers, List<DNSResourceRecord> txtAnswers, String [] ipAndMask, String location) {
		
		for (DNSResourceRecord ans : answers) {
			if (ans.getType() == DNS.TYPE_A) {
				try {
					InetAddress amazon = InetAddress.getByName(ipAndMask[0]);
					InetAddress ansIP = InetAddress.getByName(ans.getData().toString());
					
					int amazonIntIP = ByteBuffer.wrap(amazon.getAddress()).getInt();
					int ansIntIP = ByteBuffer.wrap(ansIP.getAddress()).getInt();
					int mask = Integer.parseInt(ipAndMask[1]);
					int ansbitShifted = (ansIntIP >> mask);
					int amazonbitshifted = (amazonIntIP >> mask);
					
					System.out.println("ansbitShifted: " + ansbitShifted + ", amazonbitshifted: " + amazonbitshifted);
					
					if (ansbitShifted == amazonbitshifted) {
						DNSRdataString s = new DNSRdataString(location + "-" + ansIP.getHostAddress());
						DNSRdata data = (DNSRdata)s;
						DNSResourceRecord newTxtAnswer = new DNSResourceRecord(ans.getName(), DNS.TYPE_TXT, data);
						newTxtAnswer.setTtl(ans.getTtl());
						txtAnswers.add(newTxtAnswer);
					}
					
				} catch (UnknownHostException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return true;
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
	
	
	
	
	public static InetAddress resolveARecordForNS(DNSResourceRecord nsToResolve, InetAddress addr, DatagramSocket sendSocket) throws IOException {
		System.out.println("------------ Inside resolveARecordForNS ----------------------");
		
		InetAddress resolveIPAddress = null;
		
		HashSet<String> visitedNameServers = new HashSet<>();
		boolean recursionDesired = true;
		
		// Construct DNS Request
//		DNS dnsRequest = new DNS();
//		dnsRequest.setOpcode(DNS.OPCODE_STANDARD_QUERY);
//		dnsRequest.setRcode(DNS.RCODE_NO_ERROR);
//		dnsRequest.setAuthoritative(true);
//		dnsRequest.setRecursionDesired(recursionDesired);
//		dnsRequest.setRecursionAvailable(false);
		
		String nameToResolve = nsToResolve.getData().toString();
		
		System.out.println("nameToResolve: " +  nameToResolve);
		 
		
		DNSQuestion ques = new DNSQuestion(nameToResolve, DNS.TYPE_A);
		//dnsRequest.addQuestion(ques);
		
		
		System.out.println("start IP adddress " + addr.getHostAddress() + ", " + addr.getHostName());
		
		// Temporary 
			DNSQuestion oQues = originalDNS.getQuestions().get(0);
			System.out.println("Original question: " + oQues);
			originalDNS.removeQuestion(oQues);
			System.out.println("After removing original question size of questions in original dns request: " + originalDNS.getQuestions().size());
			originalDNS.addQuestion(ques);
				
			//dnsRequest = originalDNS;	
		//
		
		System.out.println("New original DNS is");
		System.out.println(originalDNS);
		
		visitedNameServers.add(nameToResolve);
		
		System.out.println("Calling process now from resolveARecordForNS");
		DNS result = process(sendSocket, originalDNS, addr, visitedNameServers, recursionDesired, 0);
		System.out.println("process returned back to resolveARecordForNS");
		
		if (result != null) {
			List<DNSResourceRecord> answers = result.getAnswers();
						
			String ip = null;
			for (DNSResourceRecord ans : answers) {
				if (ans.getType() == DNS.TYPE_A) {
					ip = ans.getData().toString();
				}
			}
			
			if (ip != null) {
				resolveIPAddress = getIPAddrObject(ip);
			}
		}
		
		originalDNS.removeQuestion(ques);
		originalDNS.addQuestion(oQues);
		
		System.out.println("------------ Done with resolveARecordForNS ----------------------");
		return resolveIPAddress;
	}
	
	public static DNSResourceRecord ifExistsInAdditional(DNSResourceRecord target, List<DNSResourceRecord> additional, List<DNSResourceRecord> skipped) {
		DNSRdata temp = target.getData();
		
		String targetStr = temp.toString();
		
		for (DNSResourceRecord record : additional) {
			//System.out.println("targetStr: " + targetStr + ", addition: " + record.getName());
			
			// For everything except IPv6
			if (targetStr.equals(record.getName()) && record.getType() == DNS.TYPE_A) {
				return record;
			}
			
			// For IPv6 Addresses
//			if (targetStr.equals(record.getName()) && record.getType() == DNS.TYPE_AAAA && originalType == DNS.TYPE_AAAA) {
//				System.out.println("Inside returning IPv6 address");
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
			
			//System.out.println("------------------ Original request -------------------");
			//System.out.println(dns.toString());
			//System.out.println("-------------------------------------------------------");
			
			return dns;
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		return null;
	}


	public static InetAddress getIPAddrObject(String ip) throws UnknownHostException {
		InetAddress ipAddr = InetAddress.getByName(ip);
		
		
		
//		byte [] addr = new byte[4];
//		String [] subIP = ip.split("\\.");
//
//		////System.out.println("subIP: " + Arrays.toString(subIP) + ", length: " + subIP.length);
//
//		for (int i = 0; i < 4; i++) {
//			addr[i] = (byte)(Integer.parseInt(subIP[i]));
//		}
//
//		try {
//			ipAddr = InetAddress.getByAddress(addr);
//		} catch (UnknownHostException e1) {
//			e1.printStackTrace();
//		}

		return ipAddr;
	}
}
