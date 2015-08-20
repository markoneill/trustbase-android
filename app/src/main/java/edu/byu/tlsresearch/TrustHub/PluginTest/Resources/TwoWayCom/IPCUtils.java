package edu.byu.tlsresearch.TrustHub.PluginTest.Resources.TwoWayCom;

import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * Created by ben on 8/11/15.
 * Contains methods for facilitating interprocess communication (IPC) for Android.
 */
public class IPCUtils {

    private static final String TAG= "IPCUtils";

    /*
        Turns any Serializable object into a Bundle which can be passed via IPC.
     */
    public static Bundle bundle(Serializable obj)
    {
        ByteArrayOutputStream holder = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] bytes = null;
        try {
            out = new ObjectOutputStream(holder);
            out.writeObject(obj);
            bytes = holder.toByteArray();
        }
        catch (IOException e) {
            Log.e(TAG + " bundle", "Error loading output stream.");
            return null;
        }
        finally {
            //Close streams
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                holder.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }

        if(bytes != null) {
            Log.d(TAG + " bundle", "Size of serialized array: " + bytes.length);
            Bundle b = new Bundle();
            b.putByteArray("data", bytes);
            return b;
        }
        else
            return null;
    }

    /*
        Retrieves serialized objects packed using bundle(Serializable obj).
     */
    public static Object unbundle(Bundle b)
    {
        byte[] bytes = b.getByteArray("data");
        Log.d(TAG + " unbundle", "Size of retrieved array: " + bytes.length);
        Object obj = null;
        ByteArrayInputStream holder = new ByteArrayInputStream(bytes);
        ObjectInput in = null;

        try {
            in = new ObjectInputStream(holder);
            obj = in.readObject();
        }
        catch(IOException e)
        {
            Log.e(TAG + " unbundle", "Error reading from bundle");
            return null;
        }
        catch(ClassNotFoundException e)
        {
            Log.e(TAG + " unbundle", "Class not found\n" + e.getMessage());
            return null;
        }
        finally
        {
            //Close streams.
            try {if(in != null) in.close();}
            catch(IOException e) {/*Do nothing*/}

            try {holder.close();}
            catch(IOException e) {/*Do nothing*/}
        }

        return obj;
    }

}
