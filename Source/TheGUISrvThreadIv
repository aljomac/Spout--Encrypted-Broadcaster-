import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

public class TheGUISrvThreadIv extends Frame implements ActionListener
{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private Label theLabel;
	private TextField userTextField;
	public static JButton submitButton;
	private static JFrame f;
	private String theBits = null;
	ServerThread theThread;
	private JPanel thePanel;
	
	Action accept = new AbstractAction("accept")
	{
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		public void actionPerformed(ActionEvent arg0) 
		{
			theBits = userTextField.getText();//get the bits from the little box and store them temporarily 
			if(theBits.length() == 8)
			{
				theThread.setTheIv(theBits);
				theThread.setIsIvSet(true);
				f.dispose();
			}
			else
				JOptionPane.showMessageDialog(thePanel,"IV must be 8 characters long. ","Invalid IV length", JOptionPane.ERROR_MESSAGE);
		}
	};
	
	
	public TheGUISrvThreadIv(ServerThread thread)
	{
		theThread = thread;
		thePanel = new JPanel();
		
		//General Settings
		setLayout(new BorderLayout());
		
		f = new JFrame("Shout - v0.9");
		f.setVisible(true);
		f.setPreferredSize(new Dimension(350, 100));
	
		f.getContentPane().add(theLabel = new Label("Enter The IV: "), BorderLayout.NORTH);
		f.getContentPane().add(userTextField = new TextField(), BorderLayout.CENTER);
		f.getContentPane().add(submitButton = new JButton(accept), BorderLayout.LINE_START);
		f.getRootPane().setDefaultButton(submitButton);
		submitButton.setVisible(false);
		f.pack();
		userTextField.requestFocus();
		setSize(600, 400);
		setTitle("");

	}

	
	protected String getUserInput(){
		return theBits;
	}
	
	
	protected void setUserInput(String bits){
		theBits = bits;
	}
	
	
	public void actionPerformed(ActionEvent arg0) {
		
	}
}







