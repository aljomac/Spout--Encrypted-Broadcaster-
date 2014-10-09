

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
import org.apache.commons.codec.binary.Hex;


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
	private static KeyPair keyPair;
	private static SecureRandom rnd = new SecureRandom();
	private static boolean isNewClient = false;
	private static boolean isNewSet = false;


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

		//GUI Stuff
		suspendAll = true;
		theGUI = new TheGUI();
		

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
		
		

		//===============================================
		//               Setup I/O
		//===============================================
		outToServer = new DataOutputStream(clientSocket.getOutputStream()); //output to server
		BufferedReader inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream())); //buffered reader in from server
		theGUI.appendString("[System]: You are connected to: " + srvIP + "\n" + "\n");
		
		
		
		//===============================
		//        New Or Returning
		//===============================
		theGUI.appendString("[System]: Are you a new client on this server: ["+srvIP+"]\n");
		theGUI.appendString("[System]: Y or N?\n");

		while(!isNewSet){
			Thread.sleep(500);
		}

		
		//These are the variables we use to reference the clients public/private keys.
		//They are set below for both cases. (Client is new or returning)
		KeyPair theKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair(); //Generate the keys forever attached to username.
		PrivateKey privateKeyForStorage; 
		PublicKey publicKeyForStorage;

		
		
		//============================
		//        Get Username
		//============================
		/*
		 * Loop until a username is entered into the chat window. GUI sets isUsernameSet ==true
		 */
		boolean weHaveUsername = false;
	    publicKeyForStorage = null;
	    privateKeyForStorage = null;
		do
		{
			weHaveUsername = true;
			theGUI.setReadyForUsername(true);
			isUsernameSet = false;
			
			if(isNewClient)//This is where we setup new clients.
			{
				
/***************This is where usernma esetting is done, will have to change!*/
				theGUI.appendString("[System]: Please input your desired username..\n");
				while(isUsernameSet == false){
					Thread.sleep(1000);
				}
				
				//In here we are creating the username hash to be used in for identification and other things.
			    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				String usernameHash = new String(Hex.encodeHex(sha1.digest((userName).getBytes())));
				outToServer.writeBytes(usernameHash + "\n"); //send over the user name hash
				System.out.println(usernameHash);
				
				/*This sets the variables for the users RSA keys. These RSA keys are only used for the digital signature.
				These are the bytes that are going to be stored by the database for every computer, the server will keep
				a list of the username hashes and public keys while the client will store the password cipher, the salt 
				for the passwords as well as the private and public keys associated to the username hash.*/
			    publicKeyForStorage = theKeyPair.getPublic();
			    privateKeyForStorage = theKeyPair.getPrivate();
			    
			    //Get the encoded bytes for the RSA public key in order to have the server store it for authentication and data validation.
			    byte[] encodedPublic = publicKeyForStorage.getEncoded();
			    String encodedPublicString = new String(Base64.encodeBase64String(encodedPublic));
			    outToServer.writeBytes(encodedPublicString + "\n");//send encoded to server
			    
			    //Store the public key bytes in a file named username hash
				FileOutputStream keyfos2 = new FileOutputStream("C:/Users/Public/Favorites/"+usernameHash+".txt");
				keyfos2.write(encodedPublic);
				keyfos2.close();    
				
				//Store the private key in a file named usernamehash_
			    byte[] encodedPrivate = privateKeyForStorage.getEncoded();
				FileOutputStream keyfos = new FileOutputStream("C:/Users/Public/Favorites/"+usernameHash+"_.txt");
				keyfos.write(encodedPrivate);
				keyfos.close();
				
				

			}
			
			else//This is where we validate old clients, this is where we would check database for the keys.
			{
				
/***************This is where usernma esetting is done, will have to change!*/
				theGUI.appendString("[System]: Please enter your username..\n");
				while(isUsernameSet == false){
					Thread.sleep(1000);
				}
				
				//Create the hash for the given username in order to compare it.
			    MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
				String usernameHash = new String(Hex.encodeHex(sha1.digest((userName).getBytes())));
				System.out.println(usernameHash);
				
				//Setup a key factory to load our key bytes into
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");

				
				try{
					
				//path to the public key bytes
				Path path = Paths.get("C:\\Users\\Public\\Favorites\\"+usernameHash+".txt");
				
				//Read all the bytes for the public key and load it into our publicKeySpec.
				byte[] encodedPublic = Files.readAllBytes(path);
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublic);
				publicKeyForStorage = keyFactory.generatePublic(publicKeySpec);
				
				
				//Gather the private key
				Path path2 = Paths.get("C:\\Users\\Public\\Favorites\\"+usernameHash+"_.txt");
				
				//Load up the private key, this is the section where we would need passwords and to create
				//something to have it decrypt with the password, also go get the salt.
				byte[] encodedPrivate = Files.readAllBytes(path2);
				EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivate);
				privateKeyForStorage = keyFactory.generatePrivate(privateKeySpec);
				
				}
				catch(NoSuchFileException e7){
					theGUI.appendString("[System]: Could not find username, please try again.\n");
					weHaveUsername = false;
					continue;
				}
				if(weHaveUsername)
					outToServer.writeBytes(usernameHash + "\n"); //send over the user name hash
			}

		}while(!weHaveUsername);
		

		
		
		//==========================================
		//           Client Authentication
		//========================================== 
		String theCheck = inFromServer.readLine();//Wait for the server to send us randomly generated string to sign

		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte[] digest = sha1.digest(theCheck.getBytes());//Make sha1 hash with this, in order to sign it.

		//Encrypt digest with our private key we use for the digital signature. 
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, privateKeyForStorage);
		
		//Finally encode that signature in base64 in order to cleanse it during transfer.
		String encodedEncryptedSignature = new String(Base64.encodeBase64String(cipher.doFinal(digest)));

		System.out.println("the encoded signature we are sending: "+encodedEncryptedSignature);
		outToServer.writeBytes(encodedEncryptedSignature + "\n");//Write our signature out to the serve
		


		//===============================================
		//               Create first IV
		//===============================================
		/*
		 * This is the first IV that we create to use in our CBC mode.
		 * After this one is used, the new IV comes from the random crap 
		 * at the begining of every message sent over the server, it works 
		 * because everyone gets the same message so they all know the random 
		 * IV generated and sent with every message. We could include a 
		 * header with the files that are sent over the network.
		 */
		byte[] randomBytes = new byte[16];
		rnd.nextBytes(randomBytes);
		ivSpec = new IvParameterSpec(randomBytes);
		
		while(randomBytes.length != 16)
		{
			rnd.nextBytes(randomBytes);
			ivSpec = new IvParameterSpec(randomBytes);
		}
		
		

		//===============================================
		//               
		//      Send Shared secret over RSA tunnel.
		// 
		//===============================================
		
		/*
		 * Next up is the of our shared secret to be used by AES.
		 * We create brand spanking new temporary RSA keys for the 
		 * user. We then send out the required information for the 
		 * server to use the public key just made along with a hash
		 * of the public key in order to validate the bytes received.
		 */
		
		
		GenerateRSAKeys();//generate RSA keys.
		PublicKey pubKey = keyPair.getPublic();//make an instance of the public key.
		String encodedPublicString = new String(Base64.encodeBase64String(pubKey.getEncoded()));
		outToServer.writeBytes(encodedPublicString+"\n");//fire it off to the server.
		
		byte[] hashOfMessage = sha1.digest(encodedPublicString.getBytes());
		String signature = new String(Base64.encodeBase64String(cipher.doFinal(hashOfMessage)));
		outToServer.writeBytes(signature+"\n");
		
		theGUI.appendString("[System]: sent public key to server"+"\n");
		System.out.println("Signature sent to srv: "+signature);
		

		//==========================================
		//          Exchange the secret.
		//==========================================
		/*
		 * In here, we have passed over to our server thread everything it needs to make an instance
		 * of the clients pubKey. So sit and wait for the server thread to pass along the encrypted
		 * shared secret then store that sucker right in memory. It's not my problem if someone has
		 * remote execution control over YOUR pc.
		 */
		theGUI.appendString("[System]: waiting for server to input secret..."+"\n");
		
		
		//I dont know if this loop is overkill, I think it is because read line is supposed to be a blocking cal
/*********I'll have to look into it, really don't want to miss that secret! */
 
		String tempEncrypted = null;
		while((tempEncrypted = inFromServer.readLine()) == null)//keep doing it until its not null, only thing that the sever can send is the secret.
		{
			try {
				Thread.sleep(1000);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		String tempDecrypted = DecryptRSA(tempEncrypted);//Decrypt the received key with RSA
		theGUI.appendString(tempDecrypted.length()+"\n");
		byte[] sharedBytes = tempDecrypted.getBytes();
		tempDecrypted = "";
		privateSymKey = new SecretKeySpec(sharedBytes, "AES"); //create privateSymKey object with byte[]
		sharedBytes = null;
		
		
		//==========================================
		//          Enter the Main loop.
		//==========================================
		/*
		 * Pretty self explanatory part here. We sit in this loop 99% of the time. Client reads the line,
		 * decrypts the contents then appends them to the GUI as they come in from the server.
		 * 
		 * At this point we have setup our AES tunnel with the shared secret we received from the server earlier.
		 */
		
		suspendAll = false;
		boolean closeSocket = false;

		while(true)
		{
			if(!suspendAll)
			{
				try
				{
					
					String cipherTxtFromServer = inFromServer.readLine();
					if(cipherTxtFromServer != null)//Happens sometimes, I think its just a good idea to clean any null requests.
					{
						String plainTxtFromServer = Decrypt(cipherTxtFromServer, privateSymKey);//Call AESdecrypt on the message.
						SetChatDisplay(plainTxtFromServer);//Set the display
						iv = (cipherTxtFromServer.substring(1, 17)).getBytes();//Set the iv to the first 16 bytes from the message.
					}
/*******************Im not sure why this is here?*/else
					{
						SecureRandom scrRan = new SecureRandom();
						byte[] ivBytes = new byte[16];
						scrRan.nextBytes(ivBytes);
						iv = ivBytes;
					}
					ivSpec = new IvParameterSpec(iv);
					
					//Gather the cipher and shave off the first 16 bytes 
					//of the secure random pad to creat the new IV. All 
					//clients are to recieve the same cipher, at the same
					//time, so they will all have the same IV at any given
					//time. You want to be sure to change it after the msg
					//has been decrypted or else the IV used to decrypt 
					//would be the new one and not the one used to encrypt.

					
				} catch (javax.crypto.BadPaddingException e) {
					JOptionPane.showMessageDialog(theGUI.getPanel(),"The shared secret you were given: "+" (Hash: "+privateSymKey.hashCode()+")  Does not match that of the other clients connected to "+srvIP+".\nPlease contact your server admi or try to connect again.","Bad Private Key", JOptionPane.ERROR_MESSAGE);
					e.printStackTrace();
				}

				if(closeSocket)//Kill client and exit main.
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
		
		//Make a replacment int for "_". We sanitize the _ char because the messages use that to break up the cipher once decrypted.
		int temp = rnd.nextInt();
		String replacement = Integer.toString(temp);
		
		//Generate our random padding
		byte[] randomBytes = new byte[32];
		rnd.nextBytes(randomBytes);
		String random2 = new String(randomBytes);
		
		//Check the random padding for _ and replace with replacement. Again because this character is used by us, see below.
		random2 = random2.replace("_", replacement);
		
		//Get Input from GUI
		userInput = theGUI.GetUserInput();

		//Encrypt and send out to socket. This takes random2, sticks it on the front of the string
		//Then it uses the curent date and time, followed by the message. This is where we use _ in 
		//order to break up the random crap at the start from the date and time. SetChatDisplay takes care of that.
		if(!suspendAll){
			encryptedUserString = Encrypt(random2+symbol+"[" + dateFormat.format(cal.getTime())+" | " + userName+"]: "+userInput, privateSymKey);
			outToServer.writeBytes(encryptedUserString + '\n'); 
			random2 = null;
			randomBytes = null;
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
		System.out.println(plainText);
		if(plainText != null)
		{
			String[] strArray1 = plainText.split("_");//split off the random crap header used for IV
			try {
				second = strArray1[1];
			} catch (ArrayIndexOutOfBoundsException e) {
				e.printStackTrace();
			}
			
			String[] strArray2 = second.split("]");//Split the string at the ] in order to make text and time different colors.
			String userNameAndInfo = strArray2[0];//place to throw second half of string.
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
			text = "";
			second = "";
		}
	}

	//=======================================
	//
	// 			RSA ENCRYPT/DECRYPT
	//
	//=======================================
	private static void GenerateRSAKeys() throws Exception
	{
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		keyPair = keygen.generateKeyPair();
	}


	private static String DecryptRSA(String cipherText)  throws Exception
	{
		PrivateKey key = keyPair.getPrivate();
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);

		
		//decode Result and put it in a byte array
		byte[] decodedEncryptedBytes = Base64.decodeBase64(cipherText.getBytes());

		//Work Cipher magic
		String decryptedString = new String(cipher.doFinal(decodedEncryptedBytes));
		
		return decryptedString;
	}

	
	//=======================================
	//
	// 		   AES ENCRYPT/DECRYPT
	//
	//=======================================
	
	private static String Encrypt(String userInput, SecretKeySpec privateSymKey)
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, InvalidParameterSpecException,
			NoSuchAlgorithmException, NoSuchPaddingException
	{
		//Initiate cipher class
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, privateSymKey, ivSpec);//where we use the IV and the shared secret.

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
		String decryptedString = new String(c.doFinal(decodedEncryptedBytes));
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

	protected static void setIsClientNew(boolean value)
	{
		isNewClient = value;
	}
	
	protected static void setIsNewSet(boolean value)
	{
		isNewSet = value;
	}

	protected static void setUsernameSet(boolean value) 
	{
		isUsernameSet = value;
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
			System.out.println(userName);
			setUsernameSet(true);
		}
		
		srvIP = null;
	}
}





