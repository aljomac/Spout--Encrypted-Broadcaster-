import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Enumeration;
import java.util.Vector;


public class ServerThread extends Thread
{
	//I/O variables 
	protected BufferedReader inFromClient;
	protected DataOutputStream outToClient;
	protected static Socket threadSock;
	protected Thread listener;
	
	//List of all server threads active.
	protected static Vector<ServerThread> serverThreadList = new Vector<ServerThread>();//its static so the same one is used for all.
	
	//Used to suspend all regular chat functions while there is a client connecting as to free up tunnels for RSA exchange.
	private boolean suspendAll;
	
	//RSA key exchange stuff
	private String sharedBitString;
	private BigInteger n;
	private BigInteger e;
	
	//TheGUIObj
	private TheGUISrvThread theGUI;
	
	//TheIV
	private boolean isIvSet = false;
	private String theIV;
	
	public ServerThread(Socket socket, String shared, TheGUISrvThread theeGUI) throws IOException
	{
		sharedBitString = shared;//Take in the shared bits entered earlier.
		threadSock = socket;
		suspendAll = true;
		theGUI = theeGUI;
	}
	
	
	/*
	 * Ran as a starting point for the thread, it initiates the IO and starts a new thread listener. 
	 */
	public void start()
	{
		try {
				inFromClient = new BufferedReader(new InputStreamReader(threadSock.getInputStream()));
				outToClient = (new DataOutputStream(threadSock.getOutputStream()));
		    }catch (IOException e) {
			e.printStackTrace();}
		
		listener = new Thread(this);
		listener.start();
		
		try {
			outToClient.writeInt(1); //ack that the server has entered shared secret.
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	

	/*
	 * Alright so in the run method we first fire up our publicKeySwap() method in order to answer to the similar loop
	 * within the client. This is where the elements of the clients public key are transfered over in order for 
	 * this particular server thread to used them to encrypt the shared secret. Then we have 
	 */
	public void run() 
	{
		try {
			publicKeySwap();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
				e.printStackTrace();
			}
		
		try {
			createIV();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		
		serverThreadList.addElement(this);//add this element to the list of server threads.
		while(true)
		{
			try {
				Thread.sleep(500);
				sendToAll(inFromClient.readLine());//only this we want run() to do is spam send to all.
			} catch (IOException e1) {
				e1.printStackTrace();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
 
	
	/*
	 * This method sort of explains itself. It takes in the encrypted string it would recieve from its client, then 
	 * it goes down the array, sending this message to all clients currently active on the server. So long as suspendAll
	 * is not set. It is set whilst new clients are connecting.
	 */
	protected void sendToAll(String encryptedString)
	{
		if(!suspendAll)
		{
			synchronized(serverThreadList)
			{
				Enumeration<ServerThread> enumerator = serverThreadList.elements();
				while(enumerator.hasMoreElements())
				{
					ServerThread srvThread = (ServerThread)enumerator.nextElement();
					try{
						TCPServer.getGUI().getChatDisplay().append(encryptedString + "\n");
						srvThread.outToClient.writeBytes(encryptedString + '\n');
					   }catch (IOException e1) {
						e1.printStackTrace();
					}
				}
			}	
		}
	}
	
	
	/*
	 * So, this is where we join the client in gathering its public key (RSA). This works by letting 
	 * the client know when it is ready to take in the RSAe by sending it an ack bit of "1".
	 */
	
	synchronized private void publicKeySwap() throws IOException, InterruptedException
	{
		outToClient.flush();
		
		//Make sure client is ready.
		int tempVal = 0;
		boolean isClientRdy = false;
		while(!isClientRdy)
		{
			if(tempVal != 1)
				tempVal = inFromClient.read();
			if(tempVal==1)
				isClientRdy = true;
		}
		
		//===================================
		//		    Receive RSAe
		//===================================
		boolean rsaeIsSent = false;
		String temp = null;		
		outToClient.writeBytes("1"+"\n");
		System.out.println("Wrote bit 1 to client" + "\n");

		while(!rsaeIsSent)//sit in this loop until the client sends something, we know it can only be RSAe.
		{
			temp = inFromClient.readLine();
			System.out.println("This is temp: " + temp + "\n");
			
			if(temp != null)
			{
				e = new BigInteger(temp);//set our variable for e as the input from client.
				
				System.out.println("This is E: " + e + "\n");
				rsaeIsSent = true;
			}
		}
		outToClient.flush();
		outToClient.writeBytes("0"+"\n");//write out an ack bit to tell client we got it.
		System.out.println("Wrote bit 0 to client" + "\n");

		
		/*
		 * We essentially do the same thing here, just this time with the RSAn being transfered and stored for use.
		 */
		//===================================
		//		    Receive RSAn
		//===================================
		boolean rsanIsSent = false;
		temp = null;
		
		outToClient.writeBytes("1"+"\n");
		System.out.println("Wrote bit 1 to client" + "\n");
		while(!rsanIsSent)
		{
			temp = inFromClient.readLine();
			System.out.println("This is temp: " + temp + "\n");
			outToClient.flush();
			
			if(temp != null)
			{
				n = new BigInteger(temp);
				
				System.out.println("This is N: " + n + "\n");
				rsanIsSent = true;
			}
		}
		
		outToClient.flush();
		outToClient.writeBytes("0"+"\n");
		System.out.println("Wrote bit 0 to client" + "\n");
		outToClient.flush();
		
		
		//==============================
		//		Create and encrypt
		//==============================
		RSA rsa = new RSA(n, e);//create an instance with our newly found n, e.
		
		String encryptedSharedBytes = rsa.encrypt(sharedBitString);
		outToClient.writeBytes(encryptedSharedBytes + "\n");
		suspendAll = false;
		
		theGUI.setUserInput("xxxxxxxxxxxxx");//reset the bits in memory if any.
		
		System.out.println("Sent Encrypted private secret to client");
		System.out.println("SUSPEND ALL??: "+suspendAll);	
	}
	
	protected void createIV() throws IOException, InterruptedException
	{
		//===============================
		//			Send IV
		//===============================
		TheGUISrvThreadIv theGUI = new TheGUISrvThreadIv(this);
		
		while(!isIvSet){
			Thread.sleep(1000);
		}
		
		outToClient.writeBytes(theIV);
		System.out.println("wrote the iv");
		
		String ack = "0";
		while(!ack.equals("1"))
		{
			Thread.sleep(1000);
			outToClient.writeBytes(theIV + "\n");
			ack = inFromClient.readLine();
			System.out.println(ack);
		}
	}
						
	protected DataOutputStream getOutToClient() {
		return outToClient;
	}
	
	protected void setTheIv(String iv){
		theIV = iv;
	}
	
	protected void setIsIvSet(boolean isSet){
		isIvSet = isSet;
	}
	
}
