package io.otoh.otohio;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.ActionBarDrawerToggle;
import android.support.v4.widget.DrawerLayout;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.Toast;

import org.json.JSONObject;

public class SetupActivity extends Activity implements AdapterView.OnItemClickListener {

    private String accessKey = "failed";
    private String usernameString;

    private ProgressDialog pd;

    // Navigation menu start
    private DrawerLayout drawerLayout;
    private ListView drawerList;
    private String[] drawerListItems;
    private ActionBarDrawerToggle drawerListener;

    private void setupDrawer() {
        drawerListItems = getResources().getStringArray(R.array.drawer_items);
        drawerLayout = (DrawerLayout)findViewById(R.id.drawer_layout);
        drawerList = (ListView)findViewById(R.id.drawer_list_setup);
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
        setContentView(R.layout.activity_setup);

        setupDrawer();

        setTitle("Setup your account");

        //TextView textView = (TextView) findViewById(R.id.tos);
        //textView.setMovementMethod(new ScrollingMovementMethod());
    }

    public void checkAvailability(View view) {
        EditText username = (EditText) findViewById(R.id.new_username);
        usernameString = username.getText().toString();

        new AsyncTask<String, Void, String>() {
            @Override protected void onPreExecute() {
                pd = new ProgressDialog(SetupActivity.this);
                pd.setTitle("Processing...");
                pd.setMessage("Please wait.");
                pd.setCancelable(false);
                pd.setIndeterminate(true);
                pd.show();
            }

            @Override protected String doInBackground(String... arg) {
                String u = arg[0];
                otoh o = new otoh(getString(R.string.otoh_api_ca));
                JSONObject j = null;

                try {
                    j = o.createUser(u);
                    Log.i("debug", "got json object: " + j.toString());
                    return j.getString("access_key");
                } catch (Exception e) {
                    e.printStackTrace();
                }
                return "failed";
            }

            @Override protected void onPostExecute(String result) {
                Log.i("debug", "result: " + result);
                accessKey = result;

                if(accessKey.equals("failed")){
                    Log.i("debug", "we think we failed: " + accessKey);
                    Toast.makeText(SetupActivity.this, R.string.username_not_available, Toast.LENGTH_LONG).show();
                }
                else {
                    EditText email = (EditText) findViewById(R.id.email);
                    EditText nickname = (EditText) findViewById(R.id.nick_name);
                    // Saves me time during testing
                    email.setText(usernameString + "@example.com");
                    nickname.setText(usernameString + "@work");

                    Toast.makeText(SetupActivity.this, R.string.username_available, Toast.LENGTH_LONG).show();
                    getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_HIDDEN);
                    Button button = (Button) findViewById(R.id.agree_and_create);
                    button.setEnabled(true);
                }

                pd.dismiss();
            }
        }.executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, username.getText().toString());


    } // end checkAvailability

    public Boolean verifyPassword(){
        EditText password = (EditText) findViewById(R.id.password);
        EditText confirm = (EditText) findViewById(R.id.password_confirm);
        String p = password.getText().toString();
        String c = confirm.getText().toString();

        if ((!p.equals(c)) || (p.equals(""))){
            Toast.makeText(SetupActivity.this, R.string.passwords_no_not_match, Toast.LENGTH_LONG).show();
            return false;
        }

        return true;
    }

    public void agreeAndCreate(View view) {
        EditText username = (EditText) findViewById(R.id.new_username);
        EditText email = (EditText) findViewById(R.id.email);
        EditText nickname = (EditText) findViewById(R.id.nick_name);
        EditText password = (EditText) findViewById(R.id.password);

        if(!verifyPassword()){ return; }

        Intent intent = new Intent(this, GenIdentityActivity.class);
        intent.putExtra("username", username.getText().toString());
        intent.putExtra("access_key", accessKey);
        intent.putExtra("nickname", nickname.getText().toString());
        intent.putExtra("email", email.getText().toString());
        intent.putExtra("password", password.getText().toString());
        startActivity(intent);
    }

}
