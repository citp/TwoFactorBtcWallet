import javax.net.ssl.SSLSocket;
import java.io.*;

/**
 * Created by hkalodner on 11/9/14.
 */
public class TFAConnection implements Runnable {
    private static final String TAG = "TFAConnection";

    SSLSocket mSocket;
    ObjectInputStream ois;
    ObjectOutputStream oos;

    public TFAConnection(SSLSocket socket) {
        System.out.println("Creating connection");
        mSocket = socket;
        System.out.println("Still creating connection");
        new Thread(this).start();
    }

    @Override
    public void run() {
        System.out.println("Running connection");
        try {
            System.out.println("Creating input stream");
            oos = new ObjectOutputStream(mSocket.getOutputStream());
            oos.flush();
            ois = new ObjectInputStream(mSocket.getInputStream());
            System.out.println("Created output stream");
        } catch (StreamCorruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        System.out.println("Starting send");
        String msg = "This comes from computer";

        try {
            String response = (String) ois.readObject();
            System.out.println("Got response: " + response);
        } catch (OptionalDataException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        try {
            oos.writeObject(msg);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


    }

    public void tearDown() {
        try {
            mSocket.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}