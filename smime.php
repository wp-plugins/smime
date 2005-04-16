<?php
/*
Plugin Name: S/MIME Enabled e-mail
Plugin URI: http://weblog.elwing.org/elwing
Description: Allows Wordpress to send S/MIME encrypted and signed e-mails.
Version: 0.01
Author: Laura Bowser
Author URI: http://weblog.elwing.org/elwing
*/

/*  Copyright 2004  PLUGIN_AUTHOR_NAME  (email : PLUGIN AUTHOR EMAIL)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

function smimemailer($user, $subject, $message, $headers='', $htmlmessage='') {
	$options = get_option('smime_mailer');
	if (! $options['use_smime'] && ! $options['use_pgp'] )
		return @mail($user, $subject, $message, $headers);

	// We're going to use S/MIME mailing
	if ( $options['use_smime'] )
	{
		smime_send($user, $subject, $message, $headers);
	}
	elseif ($options['use_pgp'] )
	{
		smime_pgp_send($user, $subject, $message, $headers);
	}

} //end smimemailer

/*********************************
 * smime_send
 *
 * called by: smimemailer
 * calls:
 *********************************/

function smime_send($user, $subject, $message, $headers) 
{

	//Let's get the options
	$options = get_option('smime_mailer');

	//We want to verify that the $user has a key
	global $wpdb, $table_prefix;

	$id = $wpdb->get_var("SELECT id FROM ".$wpdb->users." WHERE user_email = '".$user."';");
	$key = $wpdb->get_var("SELECT smime FROM ".$table_prefix."smime_users WHERE user_id=".$id.";");

	echo "key: $key";

		$rows = $wpdb->num_rows;
	if (($rows == 0) && $options['send_on_missing'])
	{
		// There's no key, but it's OK to send without encrypting
		echo "no key, but send_on_missing enabled";
		echo "user: $user, subject: $subject, headers: $headers, Message: $message";
		@mail($user, $subject, $message, $headers);
	}

	if($rows == 1)	{
		// We have a key, let's send it!

		//openssl pkcs7 functions must read and write to files :(
		$clearfile = tempnam("temp","email");
		$encfile = $clearfile.".enc";
		$clearfile .= ".txt";

		$fp = fopen($clearfile,"w");
		fwrite($fp,$message);
		fclose($fp);

		//Do the encryption
		if (openssl_pkcs7_encrypt($clearfile,$encfile,$key,
			array("To" => $user,
					"From" => $from,
					"Subject" => $subject)))
		{
			$data = file_get_contents($encfile);

			//separate header and body, to use with mail function
			$parts = explode("\r\n",$data, 2);

			$newheaders = $header . $parts[0];

			// Send the mail!
			echo "Sending encrypted mail";
			echo "Parts1: $parts[1], headers: $newheaders";
			@mail("","",$parts[1],$newheaders);
		}

		//Unlink the temporary files:
		unlink($clearfile);
		unlink($encfile);
	}

}


/*********************************
 *  smime_create_table           
 *                               
 * Creates the smime_users table if necessary
 *
 * Called by: smime_admin_page()
 * Calls: maybe_create_table()
 *
 *********************************/
function smime_create_table() {
	global $table_prefix;

	$query = "CREATE TABLE IF NOT EXISTS ".$table_prefix."smime_users (
	user_id bigint(2) unsigned NOT NULL,
	smime longtext,
	pgp longtext,
	PRIMARY KEY (user_id) );";

	// include upgrade-functions for maybe_create_table;
	if (! function_exists('maybe_create_table')) {
		require_once(ABSPATH . '/wp-admin/upgrade-functions.php');
	}
	
	maybe_create_table($table_prefix."smime_users",$query);

}


function smime_add_pages() {
	//Add menu under options:
	add_options_page('Crypto Options', 'Crypto Options', 9, __FILE__,'smime_admin_page');
	//Add menu under users:
	add_submenu_page('profile.php', 'Encryption Keys', 'Encryption Keys', 1, __FILE__,'smime_user_page');
	//Create option in options database if not there already:
	$options = array();
	$options['use_smime'] = 0;   //use S/MIME signing/encryption
	$options['use_pgp'] = 0;  //use PGP (TODO: not enabled yet)
	$options['blog_pubcert'] = '';  //The public certificate for this weblog
	$options['blog_privatekey'] = ''; //The private key for this weblog
	$options['blog_pgp_pub'] = '';  //Blog's PGP public key
	$options['blog_pgp_private'] = '';  //Blog's PGP private key
	$options['send_on_missing'] = 1; //Send the mail unencrypted if there is not a cert for the recipient - default is yes for ease of use
	$options['always_sign'] = 0; //Should the blog always sign mails?
	$options['pgp_bin'] = '/usr/bin/gpg'; //Location of PGP/GPG binary
	$options['pgp_keyserver'] = 'subkeys.pgp.net'; //Keyserver to use

	add_option('smime_mailer', $options, 'Options for the S/MIME plugin by elwing');
}  // end smime_add_pages()


// Admin interface code
function smime_admin_page()
{

	// Create the table if needed
	smime_create_table();

	//See if user has submitted the form
	if (isset($_POST['submitted']) ) {
		$success = TRUE;
		$error = '<strong>Error:</strong>';

		$options = array();

		if (isset($_POST['enc_type']))
		{
			$options['use_smime'] = 0;
			$options['use_pgp'] = 0;
			if($_POST['enc_type'] == 1) {
				$options['use_smime'] = 1;
			}
			if($_POST['enc_type'] == 1) {
				$options['use_pgp'] = 1;
			}
		}
		if (isset($_POST['send_on_missing']) )
			$options['send_on_missing'] = 1;
		else
			$options['send_on_missing'] = 0;

		if (isset($_POST['always_sign']) )
			$options['always_sign'] = 1;
		else
			$options['always_sign'] = 0;

		if ($_POST['smimepublickey'] != '' )
		{
			// A basic check to see if the data is base64_encoded
			$purpose = openssl_x509_checkpurpose($_POST['smimepublickey'], X509_PURPOSE_ANY);
			if($purpose == -1)
			{
				//This file is not valid, reject
				$error .= ' You must provide a PEM formatted public key ';
				$success = FALSE;
			} else
				$options['blog_pubcert'] = $_POST['smimepublickey'];
		}
		else
			$options['blog_pubcert'] = '';

		if ($_POST['smimeprivatekey'] != '' )
		{
			// A basic check to see if the data is base64_encoded
			$purpose = openssl_x509_checkpurpose($_POST['smimeprivatekey'], X509_PURPOSE_ANY);
			if($purpose == -1)
			{
				//This file is not valid, reject
				$error .= ' You must provide a PEM formatted private key ';
				$success = FALSE;
			} else
				$options['blog_privatekey'] = $_POST['smimeprivatekey'];
		}
		else
		{
			if (isset($_POST['always_sign'])) 
			{
				$error .= 'In order to use Always Sign, you must provide a private key';
				$success = FALSE;
			}
			$options['blog_privatekey'] = '';
		}


		// Figure out whether they've provided a file or the PEM
/*
		if (isset($_FILES) && isset($_FILES['smimepublicfile']) ) 
		{
			// We have a file for the smime public key.
			if($_FILES['smimepublicfile']['size'] > 10240) //10K
			{
				// The file is too big for a reasonable certificate
				$success = FALSE;
				$error .= ' Your public key certificate file is too large';
			}

			// Add the contents of this file to the options:
			echo $_FILES['smimepublicfile']['tmp_name'];
			$options['blog_pubcert'] = $_FILES['smimepublicfile']['tmp_name'];
		}
*/

	

		if ($success ) 
		{
			update_option('smime_mailer', $options);
			echo '<div class="updated"><p>Plugin settings saved.</p></div>';
		}
		else
		{
			echo '<div class="updated"><p>'. $error.' </p></div>';
		}
	
	}


	//Draw the Options page for the plugin.
	$options = get_option('smime_mailer');

	$action_url = $_SERVER[PHP_SELF] . '?page=' .basename(__FILE__);

	if( $options['use_smime']  == 0) {
		$use_none = 'checked';
		$use_smime = '';
		$use_pgp = '';
	} elseif ($options['use_smime'] == 1) {
		$use_none = '';
		$use_smime = 'checked';
		$use_pgp = '';
	} else {
		$use_none = '';
		$use_smime = '';
		$use_pgp = 'checked';
	}

	$send_on_missing = $options['send_on_missing'] ? ' checked="checked"' : '';
	$always_sign = $options['always_sign'] ? ' checked="checked"' : '';
?>
	<div class='wrap'>
	<h2>S/MIME Plugin Options</h2>
	<p>S/MIME is a plugin that enables Wordpress to use S/MIME encrypted e-mails for notifications</p>

	<p><strong>Note:</strong> This plugin requires a single change to a core Wordpress file.</p>

	<p>The hack:
	<ol>
	<li>Edit the file <code>wp-includes/functions.php</code></li>
	<li>Search for the <code>wp_mail()</code> function: <br />

	<code>function wp_mail($to, $subject, $message, $headers = '') {</code></li>
    <li>At the end of that function, change <code>@mail(</code> to <code>@smimemailer(</code></li>
        </ol>
	   
	<hr />

	<form name="smimemailer" action="<?php echo $action_url; ?>" method="post">
        <input type="hidden" name="submitted" value="1" />

		  <h3>Type of Encryption to Use</h3>

		  <input type="radio" name="enc_type" value="0" <?php echo $use_none ?>> No Encryption <br />
		  <input type="radio" name="enc_type" value="1" <?php echo $use_smime ?>> S/MIME Encryption <br />
		 <!--
		  <input type="radio" name="enc_type" value="2" <?php echo $use_pgp ?>> PGP Encryption <br />
-->
		  <h3>Options</h3>
		  <p><input type="checkbox" name="send_on_missing" <?php echo $send_on_missing ?>> Send unencrypted when no recipient certificate is available </p>
<!--		  <p><input type="checkbox" name="always_sign" <?php echo $always_sign ?>> Always sign outgoing mail? (Requires Blog private key)
-->

		  <h3>Certificates and Keys</h3>
		  <p>Here, you can set the public and private keys belonging to the weblog.</p>
		  <p><strong>Caution:</strong> The private key will be stored in the database, ensure that you have appropriate protections in place.  You must provide a private key in order to enable the "Always Sign" option.</p>

			<p>S/MIME Public Certificate in PEM format</p>
<!--		 	<p><input type="file" name="smimepublicfile" size="40"></p> 
-->
			<textarea name="smimepublickey" cols="40" rows="6"><?php echo $options['blog_pubcert']; ?></textarea>

			<p>S/MIME Private Key in PEM format</p>
<!--		 	<p><input type="file" name="smimeprivatefile" size="40"></p>  -->
			<textarea name="smimeprivatekey" cols="40" rows="6"><?php echo $options['blog_privatekey']; ?></textarea>
<!--

			<p>ASCII Armored PGP Public Key</p>
		 	<input type="file" name="pgppublicfile" size="40"></p>
			<textarea name="pgppublickey" cols="40" rows="6"></textarea>

			<p>ASCII Armored PGP Private Key</p>
		 	<input type="file" name="pgpprivatefile" size="40"></p>
			<textarea name="pgpprivatekey" cols="40" rows="6"></textarea>
		 
		 -->


	<div class="submit"><input type="submit" name="Submit" value="Save changes &raquo;" /></div>
	</form>
	</div>
<?php
} // end smime_admin_page()

function smime_user_page() {

		  get_currentuserinfo();
		  	global $wpdb, $table_prefix, $user_ID;

        //See if user has submitted form
        if (isset($_POST['submitted']) ) {
		  	$success = TRUE;

				if ($_POST['smimekey'] != '' )
				{
					// A basic check to see if the data is base64_encoded
					$purpose = openssl_x509_checkpurpose($_POST['smimekey'], X509_PURPOSE_ANY);
					if($purpose == -1)
					{
						//This file is not valid, reject
						$error .= ' You must provide a PEM formatted public key ';
						$success = FALSE;
					} else {
						// Add this info to the database
						$query = "SELECT user_id from ".$table_prefix."smime_users where user_id=".$user_ID.";";
						$wpdb->query($query);
						if ($wpdb->num_rows == 1)
							$query = "UPDATE ".$table_prefix."smime_users set smime='".$_POST['smimekey']."' WHERE user_id=".$user_ID.";";
						else 
							$query = "INSERT INTO ".$table_prefix."smime_users (user_id,smime) VALUES (".$user_ID.",'".$_POST['smimekey']."');";
					
						$wpdb->query($query);
					}
				}
				else {
					// Delete the key from the database
				}

				if ($success)
                echo '<div class="updated"><p>Plugin settings saved.</p></div>';
				else 
					 echo '<div class="updated"><p> '.$error.' </p></div>';
        }

        $action_url = $_SERVER[PHP_SELF] . '?page=' .basename(__FILE__);
		  
		  //  Get the current SMIME key
		  $smimekey = $wpdb->get_var("SELECT smime from ".$table_prefix."smime_users where user_id=".$user_ID.";");

?>
        <div class='wrap'>
        <h2>Encryption Keys</h2>
        <hr />

        <form name="smimemailer" action="<?php echo $action_url ?>" method="post">
        <input type="hidden" name="submitted" value="1" />

		  <p>You can choose to upload a file with your key in it, or you can cut and paste your key</p>

		  <p>S/MIME <strong>public</strong> key in PEM format: </p>
		  <!--
		  <input type="file" size="40"></p>
		  -->
		  <textarea name="smimekey" cols=40 rows=6><?php echo $smimekey ?></textarea>

		<!--

		  <p>ASCII armored PGP <strong>public</strong> key: <br /> 
		  <input type="file" size="40"></p>
		  <textarea name="pgpkey" cols=40 rows=6></textarea>
		  -->

        <div class="submit"><input type="submit" name="Submit" value="Save changes &raquo;" /></div>
        </form>
        </div>

<?php

} // end smime_user_page()

add_action('admin_menu', 'smime_add_pages');

?>
