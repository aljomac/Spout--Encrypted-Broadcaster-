import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.JLabel;
import javax.swing.JTextField;
import javax.swing.JButton;

import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class IPSetUp extends JFrame {
	public String IPAddress = "test";
	private JPanel contentPane;
	private JTextField textField;
	private JTextField textField_1;
	private JTextField textField_2;
	private JTextField textField_3;

	/**
	 * Create the frame.
	 */
	public IPSetUp() {
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setBounds(100, 100, 370, 120);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JLabel lblNewLabel = new JLabel("Please provide the IP address of the Spout server.");
		lblNewLabel.setBounds(5, 5, 380, 15);
		contentPane.add(lblNewLabel);
		
		textField = new JTextField();
		textField.setBounds(64, 32, 46, 19);
		contentPane.add(textField);
		textField.setColumns(10);
		
		JButton btnOk = new JButton("OK");
		btnOk.setBounds(127, 62, 116, 25);
		contentPane.add(btnOk);
		btnOk.addActionListener(new ActionListener(){

	        public void actionPerformed(ActionEvent event)
	        {
	        	IPAddress = textField.getText() + "." + textField_1.getText() + "." + textField_2.getText() + "." + textField_3.getText();
	        }
	    });
		
		JLabel label = new JLabel(".");
		label.setFont(new Font("Dialog", Font.BOLD, 16));
		label.setBounds(114, 35, 15, 15);
		contentPane.add(label);
		
		textField_1 = new JTextField();
		textField_1.setColumns(10);
		textField_1.setBounds(123, 32, 46, 19);
		contentPane.add(textField_1);
		
		JLabel label_1 = new JLabel(".");
		label_1.setFont(new Font("Dialog", Font.BOLD, 16));
		label_1.setBounds(174, 35, 15, 15);
		contentPane.add(label_1);
		
		textField_2 = new JTextField();
		textField_2.setColumns(10);
		textField_2.setBounds(183, 32, 46, 19);
		contentPane.add(textField_2);
		
		JLabel label_2 = new JLabel(".");
		label_2.setFont(new Font("Dialog", Font.BOLD, 16));
		label_2.setBounds(235, 35, 15, 15);
		contentPane.add(label_2);
		
		textField_3 = new JTextField();
		textField_3.setColumns(10);
		textField_3.setBounds(245, 32, 46, 19);
		contentPane.add(textField_3);
	}

	public String IPAddress() {
		// TODO Auto-generated method stub
		return IPAddress;
	}
}
