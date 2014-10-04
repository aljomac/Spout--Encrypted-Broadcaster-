import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

public class TheGUIServer extends Frame implements ActionListener
{
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private TextField userTextField;
    private JTextArea chatDisplay;
    private JScrollPane scrollPane;
    public static JButton sendButton;
    private static JFrame f;
    private boolean bitsHaveSent = false;
    private JPanel panel;
    private Color backColor;
    private Color foreColor;
    private Color backColor2;
    private Color foreColor2;
    private Color foreColor3;

    
    Action accept = new AbstractAction("accept"){

        /**
         * 
         */
        private static final long serialVersionUID = 1L;

        public void actionPerformed(ActionEvent arg0) {
            if(!bitsHaveSent)
            {
                chatDisplay.setCaretPosition(chatDisplay.getDocument().getLength());
                userTextField.setText("");    
            }
        }
    };
    
    
    public TheGUIServer()
    {
        //General Settings
        setLayout(new BorderLayout());
        
        f = new JFrame("Shout - v1.0");
        f.setVisible(true);
        f.setPreferredSize(new Dimension(500, 350));
        panel = new JPanel();

        backColor = new Color(0,42,53);
        foreColor = new Color(129,152,153);
        backColor2 = new Color(88,110,117);
        foreColor2 = new Color(203,200,189);  
        foreColor3 = new Color(42,161,152);
        
        chatDisplay = new JTextArea(5,5);
        chatDisplay.setEditable(false);
        chatDisplay.setBackground(backColor);
        chatDisplay.setForeground(foreColor3);
        
        scrollPane = new JScrollPane(chatDisplay);
        setPreferredSize(new Dimension(450, 110));
        f.getContentPane().add(scrollPane, BorderLayout.CENTER);
        
        f.getContentPane().add("South", userTextField = new TextField());
        f.getContentPane().add(sendButton = new JButton(accept), BorderLayout.LINE_START);
        f.getRootPane().setDefaultButton(sendButton);
        sendButton.setVisible(false);
        f.pack();
        userTextField.requestFocus();
        setSize(600, 400);
        setTitle("");
    }
    
    protected JTextArea getChatDisplay(){
        return chatDisplay;
    }
    
    protected void setChatDisplay(String input)
    {
        chatDisplay.append(input);
    }

    protected JPanel getPanel()
    {
        return panel;
    }
    
    JButton theButton = new JButton(accept);
    
    public void actionPerformed(ActionEvent arg0) {
        
    }
}

