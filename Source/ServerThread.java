
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
		//Make sure the server never creates more than x ammount of threads.
		if(ServerThread.serverThreadList.size() < 15)
			acceptMore = true;


		while(acceptMore)
		{
			if(ServerThread.serverThreadList.size() <= 15)
			{
				Socket serverThreadSocket = serverSocket.accept();//wait until tcp handshake happens on port 6874
				theGui.setChatDisplay("Client Connected: " + serverThreadSocket.getInetAddress() + "\n");

				
				ServerThread srvThread = new ServerThread(serverThreadSocket, sharedString);//create new thread of server for every client.
				srvThread.start();
			}
			else
				theGui.setChatDisplay("Client was rejected. Too many clients already connected." + "\n");
		}
	}
	

	
	protected static TheGUIServer getGUI(){
		return theGui;
	}
}





