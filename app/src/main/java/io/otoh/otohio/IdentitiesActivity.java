package io.otoh.otohio;

import android.app.Activity;
import android.app.ListActivity;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.ActionBarDrawerToggle;
import android.support.v4.widget.DrawerLayout;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListAdapter;
import android.widget.ListView;
import android.widget.SimpleAdapter;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.HashMap;


public class IdentitiesActivity extends ListActivity implements AdapterView.OnItemClickListener {

    Intent intent;
    TextView identityName;
    DBUtils dbUtils = new DBUtils(IdentitiesActivity.this);

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
            Intent intent = new Intent(IdentitiesActivity.this, IdentitiesActivity.class);
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
        setContentView(R.layout.activity_identities);

        setTitle("Your Identities");

        ArrayList<HashMap<String, String>> identitiesList = dbUtils.getIdentities();
        ListView listView = getListView();
        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> arg0, View view, int arg2, long arg3) {
                identityName = (TextView) view.findViewById(R.id.identity_name);
                String identityNameValue = identityName.getText().toString();
                Intent intent = new Intent(getApplication(), IdentityActivity.class);
                intent.putExtra("identityName", identityNameValue);
                startActivity(intent);
            }
        });

        ListAdapter adapter = new SimpleAdapter(
                IdentitiesActivity.this, identitiesList, R.layout.identities_entry,
                new String[] {"identityName"},
                new int[] {R.id.identity_name});

        setListAdapter(adapter);


    }




}
