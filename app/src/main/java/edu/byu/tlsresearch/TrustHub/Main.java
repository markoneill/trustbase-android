package edu.byu.tlsresearch.TrustHub;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.support.v7.app.ActionBarActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import edu.byu.tlsresearch.TrustHub.Controllers.FromApp.VPNServiceHandler;


public class Main extends ActionBarActivity implements View.OnClickListener
{
    VPNServiceHandler service = null;
    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_tlsanalyzer);
        findViewById(R.id.startButton).setOnClickListener(this);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu)
    {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_tlsanalyzer, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item)
    {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings)
        {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onClick(View v)
    {
//        Intent intent = new Intent(this, VPNActivity.class);
//        startActivity(intent);
        Intent intent = VpnService.prepare(this);
        if (intent != null)
        {
            startActivityForResult(intent, 0);
        } else
        {
            onActivityResult(0, Activity.RESULT_OK, null);
        }
    }
    @Override
    protected void onActivityResult(int request, int result, Intent data)
    {
        if (result == RESULT_OK)
        {
            Intent intent = new Intent(this, VPNServiceHandler.class);
            startService(intent);
        }
    }
}
