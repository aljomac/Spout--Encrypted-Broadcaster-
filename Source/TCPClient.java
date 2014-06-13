import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.swing.JOptionPane;
import javax.swing.text.BadLocationException;

import org.apache.commons.codec.binary.Base64;


public class TCPClient
{
	private static byte[] iv = null;
	private static IvParameterSpec ivSpec;
	private static TheGUI theGUI; //instance of the client GUI

	//========================
	//     IO variables
	//========================
	private static DataOutputStream outToServer;
	private static SecretKeySpec privateSymKey; // yeah I know, private key sits in memory
	private static boolean isSrvSet = false;
	private static boolean suspendAll = false;
	private static String srvIP = null;


	//=========================
	//     Chat Variables
	//=========================
	private static String userName = null;
	private static boolean isUsernameSet = false;


	//============================
	//    IP Check variables
	//============================
	private static Pattern VALID_IPV4_PATTERN = null;
	private static Pattern VALID_IPV6_PATTERN = null;
	private static final String ipv4Pattern = "(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])";
	private static final String ipv6Pattern = "([0-9a-f]{1,4}:){7}([0-9a-f]){1,4}";

	static {
		VALID_IPV4_PATTERN = Pattern.compile(ipv4Pattern, Pattern.CASE_INSENSITIVE);
		VALID_IPV6_PATTERN = Pattern.compile(ipv6Pattern, Pattern.CASE_INSENSITIVE);
	}

	
	public static void main(String argv[]) throws Exception
	{
		suspendAll = true;

		//GUI Stuff
		theGUI = new TheGUI();

		//============================
		//      Get Username
		//============================
		/*
		 * Loop until a username is entered into the chat window. GUI sets isUsernameSet ==true
		 */
		theGUI.appendString("[System]: Please input your desired username..\n");
		while(!isUsernameSet){
			Thread.sleep(1000);
		}

		//============================
		//       Get ServerIP
		//============================
		theGUI.appendString("[System]: Please input the server address and press enter...\n");

		/*
		 * Just loop until a valid IP is entered in terms of string structure.
		 * Then we will look for a timeout exception.
		 */
		
		srvIP = null;
		Socket clientSocket = null; //Had to start it here or else the code complains.
		while(isSrvSet == false)
		{
			Thread.sleep(1000);

			if(srvIP != null)
			{
				theGUI.appendString("[System]: Attempting to connect to: "+"'"+srvIP+"'"+" please wait...\n");

				if(!isIpAddress(srvIP))
				{
					JOptionPane.showMessageDialog(theGUI.getPanel(), "The IP address: "+"'"+srvIP+"'"+" is not valid.\n"+"Please try again.","Invalid IP", JOptionPane.ERROR_MESSAGE);
					theGUI.appendString("[System]: Please input the server address and press enter...\n");
					srvIP = null;
				}

				if(srvIP != null && isIpAddress(srvIP))
				{
					isSrvSet = true;

					//Create client socket if we have a valid IP entered.
					try {
						clientSocket = new Socket(srvIP, 6874);
					} catch (ConnectException e1) {//catch the timeout exception and restart the process.
						JOptionPane.showMessageDialog(theGUI.getPanel(), "Connection timed out when attempting to connect to: "+"'"+srvIP+"'"+"\n"+"Please try again.","Timed Out", JOptionPane.ERROR_MESSAGE);
						isSrvSet = false;
						srvIP = null;
						e1.printStackTrace();
					}
				}
			}
		}


		//set I/O
		outToServer = new DataOutputStream(clientSocket.getOutputStream()); //output to server
		BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); //buffered reader in from server


		theGUI.appendString("[System]: You are connected to: " + srvIP + "\n" + "\n");

		/*
		 * waiting for the server to input the shared secret, acks us a 1 when it is finished.
		*/
		theGUI.appendString("[System]: waiting for server to input secret..."+"\n");
		int aCheck;
		boolean theCheck = false;
		while(!theCheck)
		{
			Thread.sleep(1000);//wait 1 second.

			aCheck = inFromServer.read();// try and get the ack

			if(aCheck == 1)
				theCheck = true;

			theGUI.appendString("[System]: Waiting for a 1 ack from server "+aCheck+"\n");

		}

		outToServer.writeInt(1);//Response to the wait in serverthread.publicKeySwap();
		
		
		//===============================================
		//               RSA KeyPairing.
		//===============================================
		RSA rsa = new RSA(1024); //1024 bit rsa key
		rsa.generateKeys(); //create client side pub/private key paring in RSA
		BigInteger rsaE = rsa.getE(); //get rsa e value
		BigInteger rsaN = rsa.getN(); //get rsa n value


		//===================================
		//          Send over RSAe
		//===================================
		boolean serverACKe = false;//ack bit for the loop below
		boolean serverACKn = false;//ack bit for the loop below


		/*
		 * So essentially what this loop does is assume we have made a valid connection
		 * to the server already. A server thread is created for the specific client and
		 * is by now also in a similar loop in order to receive the clients rsa pubKey.
		 *
		 * How this works is by a series of ACK's because we only have the I/O pipeline
		 * established so only way to transfer our key is a stream of bits. So start with
		 * the server thread sending us an ack bit of 1 until. This one is sent and stored
		 * if "check" and updated with every pass of the while. For every 1, the client
		 * continues to send its E portion of the public key. This continues until the server
		 * acks with a 0 that it has received the E value and then "check2" is set and we then
		 * exit that loop, repeating the same thing for the N portion of the public key.
		 */
		String check = null;
		String check2 = null;
		while(!serverACKe)
		{
			if(check == null)
				check = inFromServer.readLine();

			if(check.equals("1"))
			{
				outToServer.writeBytes(rsaE.toString() + "\n"); //send the E of rsa public key.
				check2 = inFromServer.readLine();
			}
			if(check2.equals("0"))
				serverACKe = true;
		}


		//===================================
		//         Send over RSAn
		//===================================
		String checkn = null;
		String checkn2 = null;
		outToServer.flush();

		while(!serverACKn)
		{
			if(checkn == null)
				checkn = inFromServer.readLine();

			if(checkn.equals("1"))
			{
				outToServer.writeBytes(rsaN.toString() + "\n"); //send the E of rsa public key.
				checkn2 = inFromServer.readLine();
			}

			if(checkn2.equals("0"))
				serverACKn = true;
		}

		//==========================================
		//          Exchange the secret.
		//==========================================
		/*
		 * In here, we have passed over to our server thread everything it needs to make an instance
		 * of the clients pubKey. So sit and wait for the server thread to pass along the encrypted
		 * shared secret, given to it by the server admin [to be changed in the future]. Finish with
		 * ack'ing a 1 back to server.
		 */

		String tempEncrypted = null;
		while(tempEncrypted == null)//keep doing it until its not null, only thing that the sever can send is the secret.
		{
			tempEncrypted = inFromServer.readLine();

			if(tempEncrypted != null)
				outToServer.writeBytes("1" + "\n");
		}

		String tempDecrypted = rsa.decrypt(tempEncrypted);//Decrypt the received key with RSA
		theGUI.appendString("[System]: This is your private key: "+tempDecrypted.toString()+ "\n"+"\n");
		privateSymKey = new SecretKeySpec(tempDecrypted.getBytes(), "AES"); //create privateSymKey with byte[]
		tempDecrypted = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
		
		
		//=========================================
		// 			   Wait for IV
		//=========================================
		/*
		 * Nothing new here just passing along the IV, creating it then wiping out temp values.
		 */
		theGUI.appendString("[System]: Waiting for server to input IV \n"); 
		String tempValue = null;
		outToServer.flush();
		
		while(tempValue == null)
		{
			tempValue = inFromServer.readLine(); 
		}
		
		iv = tempValue.getBytes();
		ivSpec = new IvParameterSpec(iv);
		theGUI.appendString("[System]: IV received, welcome to the server "+userName+"\n"); 
		
		String rewrite = "get cho hands off my iv";
		iv = rewrite.getBytes();
		outToServer.flush();
		
		//Regular client funtion starts. When true suspendAll does just that, suspends all msgs.
		suspendAll = false;
		
		
		//==========================================
		//          Enter the Main loop.
		//==========================================
		/*
		 * Pretty self explanatory part here. We sit in this loop 99% of the time. Client reads the line,
		 * decrypts the contents then appends them to the GUI as they come in from the server.
		 */
		boolean closeSocket = false;

		while(true)
		{
			if(!suspendAll)
			{
				try
				{
					Thread.sleep(500);
					String cipherTxtFromServer = inFromServer.readLine();
					String plainTxtFromServer = Decrypt(cipherTxtFromServer, privateSymKey);
					SetChatDisplay(plainTxtFromServer);
				} catch (javax.crypto.BadPaddingException e) {
					JOptionPane.showMessageDialog(theGUI.getPanel(),"The shared secret you were given: "+" (Hash: "+privateSymKey.hashCode()+")  Does not match that of the other clients connected to "+srvIP+".\nPlease contact your server admin.","Bad Private Key", JOptionPane.ERROR_MESSAGE);
					e.printStackTrace();
				}

				if(closeSocket)
				{
					clientSocket.close();
					break;
				}
			}
		}
	}


	/*
	 * This method is used with the GUI. When the user presses enter, the GUI grabs the
	 * text from the userTextField, encrypts the contents and then fires it into the buffer
	 * reader on the server thread side.
	 */
	protected static void SendMessage() throws InvalidKeyException, IllegalBlockSizeException,
	BadPaddingException, InvalidAlgorithmParameterException, InvalidParameterSpecException,
	NoSuchAlgorithmException, NoSuchPaddingException, IOException
	{
		String userInput = "";
		String encryptedUserString;
		String symbol = "_";
		
		DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
		Calendar cal;
		cal = Calendar.getInstance();
		
		SecureRandom rnd = new SecureRandom();

		int random1 = rnd.nextInt(256);
		int random2 = rnd.nextInt(random1);
		
		//Get Input from GUI
		userInput = theGUI.GetUserInput();

		//Encrypt and send out to socket.
		if(!suspendAll){
			encryptedUserString = Encrypt(random2+symbol+"[" + dateFormat.format(cal.getTime())+" | " + userName+"]: "+userInput, privateSymKey);
			outToServer.writeBytes(encryptedUserString + '\n'); // <-- Dont forget \n for .readLine()
		}
	}


	/*
	 * sets the chat display in the GUI for a given string. When the string arrives it
	 * is made up of a random number of random length, followed by a special character
	 * that is made to denote the end of the random. It then splits the txt at this 
	 * special character, knowing that the first part is that random mess, second part
	 * is going to be the start of our IV+string (string starts with "["). We then sort
	 * of do this split process again in order to do the proper color formatting for the
	 * GUI (Being able to make the info and msg different colors.)
	 * 
	 *  As an added bonus the time being included in the plaintext adds a little bit of
	 *  extra random. The special character is the only recurring thing but by using CBC
	 *  there is no way it will look the same in any cipher as the blocks before it are 
	 *  our random number of random length.
	 */
	private static void SetChatDisplay(String plainText) throws BadLocationException
	{
		String second ="";
		
		if(plainText != null)
		{
			
			String[] strArray1 = plainText.split("_");
			try {
				second = strArray1[1];
			} catch (ArrayIndexOutOfBoundsException e) {
				e.printStackTrace();
			}
			
			String[] strArray2 = second.split("]");
			String userNameAndInfo = strArray2[0];
			String text = "";

			try {
				text = strArray2[1];
			} catch (ArrayIndexOutOfBoundsException e) {
				e.printStackTrace();
			}

			theGUI.appendInformation(userNameAndInfo+"]");
			theGUI.appendUserText(text + "\n");
			theGUI.getChatDisplay().setCaretPosition(theGUI.getChatDisplay().getDocument().getLength());
		
			plainText = "";
			second = "";
		}
	}


	private static String Encrypt(String userInput, SecretKeySpec privateSymKey)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, InvalidParameterSpecException,
			NoSuchAlgorithmException, NoSuchPaddingException
	{
		//Initiate cipher class
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, privateSymKey, ivSpec);

		//Encode and encrypt
		String encodedEncryptedString = new String(Base64.encodeBase64String(c.doFinal(userInput.getBytes())));
		return encodedEncryptedString;
	}


	
	private static String Decrypt(String encryptedUserInput, SecretKeySpec privateSymKey)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException,
			NoSuchAlgorithmException, NoSuchPaddingException
    {
		//Initiate Cipher
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.DECRYPT_MODE, privateSymKey, ivSpec);

		//decode Result and put it in a byte array
		byte[] decodedEncryptedBytes = Base64.decodeBase64(encryptedUserInput.getBytes());

		//Work Cipher magic
		String decryptedString = new String(c.doFinal(decodedEncryptedBytes), "UTF-8");
		return decryptedString;
	}


	protected static boolean isIpAddress(String ipAddress)
	{
		java.util.regex.Matcher m1 = VALID_IPV4_PATTERN.matcher(ipAddress);
		if (m1.matches()) {
			return true;
		}
		java.util.regex.Matcher m2 = VALID_IPV6_PATTERN.matcher(ipAddress);
		return m2.matches();
	}


	protected static void SetSrvIP(String getUserInput) {
		srvIP = getUserInput;
	}


	protected static boolean getIsSrvSet() {
		return isSrvSet;
	}


	protected static void setIsSrvSet(boolean value) {
		isSrvSet = value;
	}

	protected static void setSuspendAll(boolean setter) {
		suspendAll = setter;
	}

	protected static boolean isSuspendAll()
	{
		return suspendAll;
	}


	protected static boolean isUsernameSet() {
		return isUsernameSet;
	}


	protected static void setUsernameSet(boolean isUsernameSet) 
	{
		TCPClient.isUsernameSet = isUsernameSet;
	}

	protected static String getUserName() {
		return userName;
	}

	protected static void setUserName(String userName) throws BadLocationException 
	{
		if(userName.length() > 16)
		{
			JOptionPane.showMessageDialog(theGUI.getPanel(), "Usernames must be no greater than 16 characters.\n"+"Please try again.","Invalid Username", JOptionPane.ERROR_MESSAGE);
			theGUI.appendString("[System]: Please input your desired username..\n");
		}
		else
		{
			TCPClient.userName = userName;
			setUsernameSet(true);
		}
		
		srvIP = null;
	}
}
