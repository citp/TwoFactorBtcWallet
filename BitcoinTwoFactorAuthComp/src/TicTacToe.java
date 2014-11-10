import java.util.HashMap;
import java.nio.*;
import java.nio.channels.*;
import java.net.InetSocketAddress;
import javax.swing.*;
import javax.swing.event.*;
import com.apple.dnssd.*;

// Our TicTacToe object does the following:
// 1. It's a JFrame window. It's a DNSSD BrowseListener so it
//    gets add and remove events to tell it what to show in the window,
//    and a ListSelectionListener so it knows what the user clicked.
// 2. It listens for incoming connections. It opens a listening TCP
//    socket and advertises the listening TCP socket with DNS-SD.
//    It's our RegisterListener, so that it knows our advertised name:
//     - To display it in the window title bar
//     - To exclude it from the list of discovered peers on the network

// To safely call Swing routines to update the user interface,
// we have to call them from the Swing event-dispatching thread.
// To do this, we make little Runnable objects where necessary
// and pass them to SwingUtilities.invokeAndWait(  ). This makes
// their run(  ) method execute on event-dispatching thread where
// it can safely make the calls it needs. For more details, see:
// <http://java.sun.com/docs/books/tutorial/uiswing/misc/threads.html>

public class TicTacToe extends JFrame implements Runnable,
        RegisterListener, BrowseListener, ListSelectionListener
{
    public static void main(String[] args)
    {
        Runnable runOnSwingThread = new Runnable(  )
        { public void run(  ) { new TicTacToe(  ); } };
        try { SwingUtilities.invokeAndWait(runOnSwingThread); }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    public static final String ServiceType = "_tic-tac-toe-ex._tcp";
    public String myName;
    public HashMap activeGames;
    private DefaultListModel gameList;
    private JList players;
    private ServerSocketChannel listentingChannel;
    private int listentingPort;

    // NOTE: Because a TicTacToe is a JFrame, the caller MUST be running
    // on the event-dispatching thread before trying to create one.
    public TicTacToe(  )
    {
        super("Tic-Tac-Toe");
        try
        {
            // 1. Make the browsing window, and start browsing
            activeGames = new HashMap(  );
            gameList = new DefaultListModel(  );
            players = new JList(gameList);
            players.addListSelectionListener(this);
            getContentPane(  ).add(new JScrollPane(players));
            setSize(200, 300);
            setDefaultCloseOperation(EXIT_ON_CLOSE);
            setVisible(true);
            DNSSD.browse(ServiceType, this);

            // 2. Make listening socket and advertise it
            listentingChannel = ServerSocketChannel.open(  );
            listentingChannel.socket(  ).bind(new InetSocketAddress(0));
            listentingPort = listentingChannel.socket(  ).getLocalPort(  );
            setTitle(listentingPort + " registering");
            DNSSD.register(null, ServiceType, listentingPort, this);

            // 3. If we sit here and hog the event-dispatching thread
            // the whole UI will freeze up, so instead we create a new
            // background thread to receive incoming connection requests.
            new Thread(this).start(  );
        }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    public void operationFailed(DNSSDService service, int errorCode)
    {
        System.out.println("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // If our name changes while we're running, we update window title.
    // In the event that we're registering in multiple domains (Wide-Area
    // DNS-SD) we'll use the local (mDNS) name for display purposes.
    public void serviceRegistered(DNSSDRegistration sd, int flags,
                                  String serviceName, String regType, String domain)
    {
        if (!domain.equalsIgnoreCase("local.")) return;
        myName = serviceName;
        Runnable r = new Runnable(  )
        { public void run(  ) { setTitle(listentingPort + " " + myName); } };
        try { SwingUtilities.invokeAndWait(r); }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    // Our serviceFound and serviceLost callbacks just make Adder and
    // Remover objects that safely run on the event-dispatching thread
    // so they can modify the user interface
    public void serviceFound(DNSSDService browser, int flags, int ind,
                             String name, String type, String domain)
    {
        if (name.equals(myName)) return;  // Don't add ourselves to the list
        DiscoveredInstance x = new DiscoveredInstance(ind, name, domain);
        try { SwingUtilities.invokeAndWait(new Adder(x)); }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    public void serviceLost(DNSSDService browser, int flags, int ind,
                            String name, String regType, String domain)
    {
        DiscoveredInstance x = new DiscoveredInstance(ind, name, domain);
        try { SwingUtilities.invokeAndWait(new Remover(x)); }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    // The Adder and Remover classes update the list of discovered instances
    private class Adder implements Runnable
    {
        private DiscoveredInstance add;
        public Adder(DiscoveredInstance a) { add = a; }
        public void run(  ) { gameList.addElement(add); }
    }

    private class Remover implements Runnable
    {
        private DiscoveredInstance rmv;
        public Remover(DiscoveredInstance r) { rmv = r; }
        public void run(  )
        {
            String name = rmv.toString(  );
            for (int i = 0; i < gameList.size(  ); i++)
            {
                if (gameList.getElementAt(i).toString(  ).equals(name))
                { gameList.removeElementAt(i); return; }
            }
        }
    }

    // When the user clicks in our list, if we already have a
    // GameBoard we bring it to the front, otherwise we make
    // a new GameBoard and initiate a new outgoing connection.
    public void valueChanged(ListSelectionEvent event)
    {
        int selected = players.getSelectedIndex(  );
        if (selected != 8-1)
        {
            DiscoveredInstance x =
                    (DiscoveredInstance)players.getSelectedValue(  );
            GameBoard game = (GameBoard)activeGames.get(x.toString(  ));
            if (game != null) game.toFront(  );
            else x.resolve(new GameBoard(this, x.toString(  ), null));
        }
    }

    // When we receive an incoming connection, GameReceiver reads the
    // peer name from the connection and then makes a new GameBoard for it.
    private class GameReceiver implements Runnable
    {
        private SocketChannel sc;
        public GameReceiver(SocketChannel s) { sc = s; }
        public void run(  )
        {
            try
            {
                ByteBuffer buffer = ByteBuffer.allocate(4 + 128);
                CharBuffer charBuffer = buffer.asCharBuffer(  );
                sc.read(buffer);
                int length = buffer.getInt(0);
                char[] c = new char[length];
                charBuffer.position(2);
                charBuffer.get(c, 0, length);
                String serviceName = new String(c);
                GameBoard game = new GameBoard(TicTacToe.this, serviceName, sc);
            }
            catch (Exception e) { e.printStackTrace(  ); }
        }
    }

    // Our run(  ) method just sits and waits for incoming connections
    // and hands each one off to a new thread to handle it.
    public void run(  )
    {
        try
        {
            while (true)
            {
                SocketChannel sc = listentingChannel.accept(  );
                if (sc != null) new Thread(new GameReceiver(sc)).start(  );
            }
        }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    // Our inner class DiscoveredInstance has two special properties
    // It has a custom toString(  ) method to display discovered
    // instances the way we want them to appear, and a resolve(  )
    // method, which asks it to resolve the named service it represents
    // and pass the result to the specified ResolveListener
    public class DiscoveredInstance
    {
        private int ind;
        private String name, domain;

        public DiscoveredInstance(int i, String n, String d)
        { ind = i; name = n; domain = d; }

        public String toString(  )
        {
            String i = DNSSD.getNameForIfIndex(ind);
            return(i + " " + name + " (" + domain + ")");
        }

        public void resolve(ResolveListener x)
        {
            try { DNSSD.resolve(0, ind, name, ServiceType, domain, x); }
            catch (DNSSDException e) { e.printStackTrace(  ); }
        }
    }
}