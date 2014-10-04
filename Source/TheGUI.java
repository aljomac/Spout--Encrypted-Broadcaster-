
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException; 
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

public class TheGUI extends Frame implements ActionListener
{

	private static final long serialVersionUID = 1L;
	private TextField userTextField;
	private JTextPane chatDisplay;
	private JTextArea chatLineDisplay;
	private JScrollPane scrollPane;
	public static JButton sendButton;
	private static JFrame f;
	private JPanel panel;
	private Color backColor;
	private Color foreColor;
	private Color backColor2;
	private Color foreColor2;
	private Color foreColor3;
	private Font textFont;
	private StyledDocument document;
	private SimpleAttributeSet keyWord;
	private boolean readyForUsername = false;
	private String userInput;

	Action accept = new AbstractAction("accept"){

		private static final long serialVersionUID = 1L;

		boolean initialIO = false;
		public void actionPerformed(ActionEvent arg0)
		{
			try{
				
				userInput = GetUserInput();

				
				if(readyForUsername == true){
					TCPClient.setUserName(userInput);
					if(userInput.length() <= 20)
						readyForUsername = false;
				}
				
				
				if(TCPClient.getIsSrvSet() == false && initialIO==false)//this is for when the client asks to set the IP
				{
					TCPClient.SetSrvIP(userInput);
				}
				
				if(TCPClient.getIsSrvSet() == true && initialIO==false)
				{
						if(userInput.equals("Y"))
						{
							TCPClient.setIsClientNew(true);
							TCPClient.setIsNewSet(true);
							initialIO = true;
							readyForUsername = true;
						}
						else if(userInput.equals("N"))
						{
							TCPClient.setIsClientNew(false);
							TCPClient.setIsNewSet(true);
							initialIO = true;
							readyForUsername = true;
						}
						else
						{
							appendString("[System]: Please Enter a valid option...\n");
						}
				}
					
					
				if(TCPClient.isSuspendAll() == false){
						TCPClient.SendMessage();
						chatDisplay.setCaretPosition(chatDisplay.getDocument().getLength());
				}
				
		

				userTextField.setText("");

			}
			catch (InvalidKeyException e1) {
				e1.printStackTrace();
			}
			catch (IllegalBlockSizeException e1) {
				e1.printStackTrace();
			}
			catch (BadPaddingException e1) {
				e1.printStackTrace();
			}
			catch (InvalidAlgorithmParameterException e1) {
				e1.printStackTrace();
			}
			catch (InvalidParameterSpecException e1) {
				e1.printStackTrace();
			}
			catch (NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			}
			catch (NoSuchPaddingException e1) {
				e1.printStackTrace();
			}
			catch (IOException e1) {
				e1.printStackTrace();
			} catch (BadLocationException e) {
				e.printStackTrace();
			}

		}
	};


	public TheGUI()
	{

		//General Settings
		setLayout(new BorderLayout());
		
		f = new JFrame("Shout - v1.0");
		f.setVisible(true);
		f.setPreferredSize(new Dimension(750, 550));
		panel = new JPanel();
		backColor = new Color(0,42,53);
		foreColor = new Color(129,152,153);
		backColor2 = new Color(88,110,117);
		foreColor2 = new Color(203,200,189);  
		foreColor3 = new Color(181,137,0);
		textFont = new Font("Menlo", Font.BOLD, 12);

		chatLineDisplay = new JTextArea();
		chatLineDisplay.setEditable(false);
		chatLineDisplay.setVisible(true);
		chatLineDisplay.setBackground(backColor2);
		chatLineDisplay.setForeground(foreColor2);

		chatDisplay = new JTextPane();
		chatDisplay.setEditable(false);
		chatDisplay.setBackground(backColor);
		chatDisplay.setForeground(foreColor);
		chatDisplay.setFont(textFont);

		document = (StyledDocument) chatDisplay.getDocument();
		
		keyWord = new SimpleAttributeSet();
		StyleConstants.setForeground(keyWord, foreColor3);
		StyleConstants.setBold(keyWord, true);
		
		userTextField = new TextField();
		userTextField.setBackground(backColor2);
		userTextField.setForeground(foreColor2);
		userTextField.setFont(textFont);

		scrollPane = new JScrollPane(chatDisplay);

		setPreferredSize(new Dimension(450, 110));

		f.getContentPane().add(scrollPane, BorderLayout.CENTER);
		f.getContentPane().add(chatLineDisplay, BorderLayout.WEST);
		f.getContentPane().add(userTextField, BorderLayout.SOUTH);
		f.getContentPane().add(sendButton = new JButton(accept), BorderLayout.EAST);
		f.getRootPane().setDefaultButton(sendButton);
		sendButton.setVisible(false);

		f.pack();

		userTextField.requestFocus();
		setSize(600, 400);
		setTitle("");
	}

	protected void appendInformation(String str) throws BadLocationException
	{
		document.insertString(document.getLength(), str, keyWord);
	}

	protected void appendUserText(String str) throws BadLocationException
	{
		document.insertString(document.getLength(), str, null);                                                
	}

	protected void appendString(String str) throws BadLocationException
	{
		document.insertString(document.getLength(), str, null);

	}

	protected JTextPane getChatDisplay(){
		return chatDisplay;
	}

	protected void setChatDisplay(String input)
	{
		chatDisplay.setText(input);
	}

	protected JPanel getPanel()
	{
		return panel;
	}


	protected String GetUserInput(){
		return userTextField.getText();
	}


	public void actionPerformed(ActionEvent arg0) {

	}
	
	protected void setReadyForUsername(boolean value)
	{
		readyForUsername = value;
	}
}


