import java.nio.*;
import java.nio.channels.SocketChannel;
import java.net.InetSocketAddress;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import com.apple.dnssd.*;

public class GameBoard extends JFrame implements ResolveListener, Runnable
{
    private TicTacToe tictactoe;
    private String name, host;
    private int port;
    SocketChannel channel;

    // If we're passed in a SocketChannel, it means we received an
    // incoming connection, so we should start receiving clicks from it.
    // If channel is null, it means our user initiated an outgoing connection,
    // so we'll get a serviceResolved callback to tell us when to proceed.
    public GameBoard(TicTacToe t, String n, SocketChannel c)
    {
        super(n);
        tictactoe = t;
        name = n;
        channel = c;
        tictactoe.activeGames.put(n, this);
        getContentPane(  ).setLayout(new GridLayout(3,3,6,6));
        getContentPane(  ).setBackground(Color.BLACK);
        for (int i = 0; i<9; i++) getContentPane(  ).add(new SquareGUI(this, i));
        setSize(200,200);
        setVisible(true);
        if (channel != null) new Thread(this).start(  );
    }

    public void operationFailed(DNSSDService service, int errorCode)
    {
        System.out.println("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // When serviceResolved is called, we send our name to the other end
    // and then fire off our thread to start receiving the opponent's clicks.
    public void serviceResolved(DNSSDService resolver, int flags, int ifIndex,
                                String fullName, String theHost, int thePort, TXTRecord txtRecord)
    {
        host = theHost;
        port = thePort;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 128);
        CharBuffer charBuffer = buffer.asCharBuffer(  );
        buffer.putInt(0, tictactoe.myName.length(  ));
        charBuffer.position(2);
        charBuffer.put(tictactoe.myName);
        try
        {
            InetSocketAddress socketAddress = new InetSocketAddress(host, port);
            channel = SocketChannel.open(socketAddress);
            channel.write(buffer);
            new Thread(this).start(  );
        }
        catch (Exception e) { e.printStackTrace(  ); }

        resolver.stop(  );
    }

    // The GameBoard's run(  ) method just sits in a loop receiving
    // clicks from the opponent and marking the indicated squares.
    public void run(  )
    {
        try
        {
            while (true)
            {
                ByteBuffer buffer = ByteBuffer.allocate(4);
                channel.read(buffer);
                int n = buffer.getInt(0);
                if (n >= 0 && n < 9)
                {
                    try { SwingUtilities.invokeAndWait(new SquareMarker(n)); }
                    catch (Exception e) { e.printStackTrace(  ); }
                }
            }
        }
        catch (Exception e) { } // Connection reset by peer!
    }

    // When we get a message from the opponent, we make a SquareMarker
    // object and run it on the event-dispatching thread so it can
    // safely do Swing calls to update the user interface
    class SquareMarker implements Runnable
    {
        private int num;
        public SquareMarker(int n) { num = n; }
        public void run(  )
        {
            SquareGUI s = (SquareGUI)getContentPane(  ).getComponent(num);
            s.setText("<html><h1><font color='blue'>O</font></h1></html>");
            s.setEnabled(false);
        }
    }

    // Each GameBoard contains nine JButtons displayed in a 3x3 grid
    class SquareGUI extends JButton implements ActionListener
    {
        private int num;
        public SquareGUI(GameBoard b, int n) { num = n; addActionListener(this); }
        public void actionPerformed(ActionEvent event)
        {
            // Mark our square with an X
            setText("<html><h1><font color='red'>X</font></h1></html>");
            setEnabled(false);
            // And tell the other end to mark the square too
            ByteBuffer buffer = ByteBuffer.allocate(4);
            buffer.putInt(0, num);
            try { channel.write(buffer); }
            catch (Exception e) { e.printStackTrace(  ); }
        }
    }
}