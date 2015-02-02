package io.otoh.otohio;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.security.KeyChain;
import android.support.v4.app.ActionBarDrawerToggle;
import android.support.v4.widget.DrawerLayout;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import org.w3c.dom.Text;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;


public class DisplayCertsActivity extends Activity implements AdapterView.OnItemClickListener {

    String dsCert;
    String keCert;
    String nickname;
    String fingerprint;
    String username;

    // Navigation menu start
    private DrawerLayout drawerLayout;
    private ListView drawerList;
    private String[] drawerListItems;
    private ActionBarDrawerToggle drawerListener;

    private void setupDrawer() {
        drawerListItems = getResources().getStringArray(R.array.drawer_items);
        drawerLayout = (DrawerLayout)findViewById(R.id.drawer_layout);
        drawerList = (ListView)findViewById(R.id.drawer_list_display);
        drawerList.setAdapter(new ArrayAdapter<String>(this, android.R.layout.simple_expandable_list_item_1, drawerListItems));
        drawerList.setOnItemClickListener(new DrawerItemClickListener());
        drawerListener = new ActionBarDrawerToggle(this, drawerLayout, R.drawable.ic_drawer, R.string.drawer_open, R.string.drawer_close);
        drawerLayout.setDrawerListener(drawerListener);
        getActionBar().setHomeButtonEnabled(true);
        getActionBar().setDisplayHomeAsUpEnabled(true);
        drawerList.setOnItemClickListener(this);
    }

    private class DrawerItemClickListener implements ListView.OnItemClickListener {
        @Override
        public void onItemClick(AdapterView parent, View view, int position, long id) {
            selectItem(position);
        }
    }

    private void selectItem(int position) {
        if(position == 0){
            Intent intent = new Intent(DisplayCertsActivity.this, IdentitiesActivity.class);
            startActivity(intent);
        }
        else if(position == 1){
            // scan
        }
        else if(position == 2){
            // contacts
        }
        else if(position == 3){
            // search
        }
        else if(position == 4){
            // account
        }
        else if(position == 5){
            // settings
        }

    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long it){

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if(drawerListener.onOptionsItemSelected(item)) { return true; }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        super.onPostCreate(savedInstanceState);
        drawerListener.syncState();
    }
    // Navigation menu end

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_display_certs);

        setupDrawer();

        setTitle("Install Certificates");

//        displayCerts();
        Intent intent = getIntent();
        fingerprint = intent.getStringExtra("fingerprint");
        dsCert = intent.getStringExtra("dsCert");
        keCert = intent.getStringExtra("keCert");
        nickname = intent.getStringExtra("nickname");
        username = intent.getStringExtra("username");

        TextView certLocation = (TextView)findViewById(R.id.cert_location);
        TextView pgpFingerprint = (TextView)findViewById(R.id.pgp_fingerprint);
        TextView dsCertView = (TextView)findViewById(R.id.dscert_display);
        TextView keCertView = (TextView)findViewById(R.id.kecert_display);

        dsCertView.setMovementMethod(new ScrollingMovementMethod());
        keCertView.setMovementMethod(new ScrollingMovementMethod());

        dsCertView.setHorizontallyScrolling(true);
        keCertView.setHorizontallyScrolling(true);

        try {
            certLocation.setText("Your certs can be found in Documents/otoh.io/" + nickname);
        } catch (Exception e) {
            e.printStackTrace();
        }
        pgpFingerprint.setText(fingerprint.replaceAll("(.{4})(?!$)", "$1 ").replaceAll("(.{25})(.*)", "$1\n$2"));
        dsCertView.setText("ds Cert:\n" + dsCert);
        keCertView.setText("ke Cert:\n" + keCert);
    }

    public void installCertificates(View view){
        try{
            File publicPath = Environment.getExternalStoragePublicDirectory("_otoh.io");
            if(!publicPath.exists()) {
                publicPath.mkdirs();
            }
            File publicDsP12 = new File(publicPath, "ds-" + nickname + ".p12");
            FileInputStream fin = new FileInputStream(new File(getApplicationContext().getFilesDir(), "ds-" + nickname + ".p12"));
            FileOutputStream fout = new FileOutputStream(publicDsP12);
            // Transfer bytes from in to out
            byte[] buf = new byte[1024];
            int len;
            while ((len = fin.read(buf)) > 0) {
                fout.write(buf, 0, len);
            }
            fin.close();
            fout.close();
            Log.i("++++debug", getApplicationContext().getFilesDir() + "/ds-" + nickname + ".p12 copied to " + getApplicationContext().getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS));

            File publicKeP12 = new File(publicPath, "ke-" + nickname + ".p12");
            fin = new FileInputStream(new File(getApplicationContext().getFilesDir(), "ke-" + nickname + ".p12"));
            fout = new FileOutputStream(publicKeP12);
            // Transfer bytes from in to out
            buf = new byte[1024];
            while ((len = fin.read(buf)) > 0) {
                fout.write(buf, 0, len);
            }
            fin.close();
            fout.close();
            Log.i("++++debug", getApplicationContext().getFilesDir() + "/ke-" + nickname + ".p12 copied to " + getApplicationContext().getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS));
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            // Install the DS cert
            String alias = "ds-" + nickname;
            String p12filename = alias + ".p12";
            Intent intent = KeyChain.createInstallIntent();
            byte[] p12Bytes = org.apache.commons.io.FileUtils.readFileToByteArray(new File(getApplicationContext().getFilesDir(), p12filename));
            intent.putExtra(KeyChain.EXTRA_PKCS12, p12Bytes);
            intent.putExtra(KeyChain.EXTRA_NAME, alias);
            startActivity(intent);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            // Install the KE cert
            String alias = "ke-" + nickname;
            String p12filename = alias + ".p12";
            Intent intent = KeyChain.createInstallIntent();
            byte[] p12Bytes = org.apache.commons.io.FileUtils.readFileToByteArray(new File(getApplicationContext().getFilesDir(), p12filename));
            intent.putExtra(KeyChain.EXTRA_PKCS12, p12Bytes);
            intent.putExtra(KeyChain.EXTRA_NAME, alias);
            startActivity(intent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


}
