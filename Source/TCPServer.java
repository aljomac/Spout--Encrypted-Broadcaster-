import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class TCPServer 
{
	private static ArrayList<ServerThread> threadList = new ArrayList<ServerThread>();//array of server threads for concurrency
//	private String sharedString;//placeholder for the secret bits sent to each instance of server thread.
	private static boolean bitsEntered = false;//to make loop wait for bits entered.
	final static TheGUIServer theGui = new TheGUIServer();//the servers GUI
	private static SecureRandom secureRnd = new SecureRandom();

	public TCPServer(Socket socket)	{
	}
	

	public static void main(String[] args) throws IOException, InvalidKeyException,
		IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
			NoSuchAlgorithmException, NoSuchPaddingException, InterruptedException, NoSuchProviderException
	{
		final ServerSocket serverSocket = new ServerSocket(6874);
		
		//Create new Secure random obj in order to generate our
		//private key. It will be a 128 bit AES key. The secure
		//random class seeds from environment sources of entropy
		//along with a wide selection of results making it a good
		//source of pseudo random junk.
		final int AES_KEY_SIZE = 16;
		
		byte[] temp = new byte[AES_KEY_SIZE];
		secureRnd.nextBytes(temp);
		String sharedString = new String(temp);
		theGui.setChatDisplay(sharedString + "\n");
		theGui.setChatDisplay(sharedString.length() + "\n");
		
		theGui.setChatDisplay("Waiting for clients......" + "\n");
		
		//In order to start our nested while, accept more is set to false but has the check
		//before every pass of the inner acceptMore in order to see if the size is ok for 
		//our serverThread list.
		boolean acceptMore = false;	
		while(!acceptMore)
		{
			if(ServerThread.serverThreadList.size() < 15)
				acceptMore = true;
			
			while(acceptMore)
			{
				Socket client = serverSocket.accept();//wait until tcp handshake happens on port 6874
				theGui.setChatDisplay("Client Connected: " + client.getInetAddress() + "\n");
				
				if(ServerThread.serverThreadList.size() >= 15)
				{
					theGui.setChatDisplay("Client: "+client.getInetAddress()+
							" was rejected. Too many clients already connected." + "\n");

					acceptMore = false;
					client.close();
				}
				else
				{	
					ServerThread srvThread = new ServerThread(client, sharedString);//create new thread of server for every client.
					srvThread.start();
				}
			}
		}
	}
	
	protected static boolean areBitsEntered()
	{
		return bitsEntered;
	}
	
	protected void setBitsEntered(boolean bits)
	{
		bitsEntered = bits;
	}
	
	protected static TheGUIServer getGUI(){
		return theGui;
	}
}





