<?php
/*
Plugin Name: S/MIME Enabled e-mail
Plugin URI: http://weblog.elwing.org/elwing
Description: Allows Wordpress to send S/MIME encrypted and signed e-mails.
Version: 0.03
Author: Elwing
Author URI: http://weblog.elwing.org/elwing
*/

/*  Copyright 2005 Elwing  (email : elwing@elwing.org)

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

/* The wp-mail implementation for 1.5.1: */
/* TODO: Other plugins implementing wp_mail can override this! */
if ( !function_exists('wp_mail') ) :
function wp_mail($user,$subject, $message, $headers='') {
	// Only calls the smimemailer
	@smimemailer($user,$subject, $message, $headers);
}
endif;

function smimemailer($user, $subject, $message, $headers='', $htmlmessage='') {
	$options = get_option('smime_mailer');
	if (! $options['use_smime'] && ! $options['use_pgp'] )
		return @mail($user, $subject, $message, $headers);

	// We're going to use S/MIME mailing
	if ( $options['use_smime'] )
	{
		return @smime_send($user, $subject, $message, $headers);
	}
	elseif ($options['use_pgp'] )
	{
		return @smime_pgp_send($user, $subject, $message, $headers);
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

	// Let's get all the headers
	$tmp = explode("\r\n",$headers);

	$ext_headers = "";
		
	$to_rcpt = array();
	$cc_rcpt = array();
	$bcc_rcpt = array();
	$from = get_option('admin_email');

	foreach ($tmp as $hdr) {
		list($name, $value) = explode(": ", $hdr); 
		switch (strtolower($name)) {
			case "":
				// Sometimes has a blank header value (\r\n at the end)
				break;
			case "to":
				array_push($to_rcpt, $value);
				break;
			case "cc":
				array_push($cc_rcpt, $value);
				break;
			case "bcc":
				array_push($bcc_rcpt, $value);
				break;
			case "from":
				$from = $value;
			default:
				$ext_headers .= "$name: $value\r\n";
				break;
		}
	}

	//Make sure we have all the recipients from $user: (with no spaces)
	$user_rcpts = preg_split("/,(\s)*/",$user);

	// We have all the recipients, let's find out which ones are encrypted and which aren't
	$rcpts = array_merge($to_rcpt, $cc_rcpt, $bcc_rcpt, $user_rcpts);


	//We want to verify that the $user has a key
	global $wpdb, $table_prefix;

	$enc_rcpt = array();
	$plain_rcpt = array();

	// For each recipient, see if they have a key:
	foreach ($rcpts as $rcpt) {

		$id = $wpdb->get_var("SELECT id FROM ".$wpdb->users." WHERE user_email = '".$rcpt."';");
		if(($id == null) && $options['send_on_missing']) {
			// there's no user with this e-mail
			array_push($plain_rcpt, $rcpt);
			continue;
		}
		$key = $wpdb->get_var("SELECT smime FROM ".$table_prefix."smime_users WHERE user_id=".$id.";");

		if (($key == null) && $options['send_on_missing'])
		{
			// There's no key, but we want to send things anyway:
			array_push($plain_rcpt, $rcpt);
			continue;
		}

		if($key != null)	{
			// We have a key

			array_push($enc_rcpt, array($rcpt, $key));
		}
	}

	// If there are unencrypted e-mails to send:
	if ((count($plain_rcpt) > 0) && $options['send_on_missing'])
	{

		$to = implode(",", array_intersect($plain_rcpt, $user_rcpts));
		$headers = smime_create_rcpt_hdrs("Cc", array_intersect($plain_rcpt, $cc_rcpt));
		$headers .= smime_create_rcpt_hdrs("Bcc", array_intersect($plain_rcpt, $bcc_rcpt));
		$headers .= $ext_headers;

		mail($to, $subject, $message, $headers);
	}

	if(count($enc_rcpt) > 0) {

		// We have 	encrypted mails to send
		// Unfortunately, openssl_pkcs7 cannot encrypt for multiple recipients

		//openssl pkcs7 functions must read and write to files :(
		$clearfile = tempnam("temp","email");
		$encfile = $clearfile.".enc";
		$clearfile .= ".txt";

		$fp = fopen($clearfile,"w");
		fwrite($fp,$message);
		fclose($fp);

		// This is horribly inefficient and should be fixed (somehow)

		foreach ($enc_rcpt as $rcpt) {


			//Do the encryption
			if (openssl_pkcs7_encrypt($clearfile,$encfile,$rcpt[1],
				array("To" => $rcpt[0], "From" => $from, "Subject" => $subject)))
			{
				$data = file_get_contents($encfile);
	
				//separate header and body, to use with mail function
				$parts = explode("\n\n",$data, 2);
	
				// Send the mail!
				mail($rcpt[0],$subject,$parts[1],$parts[0]);
			}
		}

		//Unlink the temporary files:
		unlink($clearfile);
		unlink($encfile);
	}

}

/*********************************
 * smime_create_rcpt_hdrs($hdr, $rcpts)
 *  creates a text string for the headers
 *
 * Called by: smime_send()
 *
 *********************************/
function smime_create_rcpt_hdrs($hdr, $rcpts) {

	$ret = "";

	if(count($rcpts) < 1)
		return $ret;

	foreach($rcpts as $rcpt) {
		$ret .= "$hdr: $rcpt\r\n";
	}

	return $ret;
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
	add_options_page('Encryption', 'Encryption', 9, __FILE__,'smime_admin_page');
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
		if(isset($_POST['use_smime']))
			$options['use_smime'] = 1;
		else
			$options['use_smime'] = 0;

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
				$error .= 'In order to use "Sign all outgoing messages", you must provide a private key';
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

/*	if( $options['use_smime']  == 0) {
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
*/

	$use_smime = $options['use_smime'] ? ' checked="checked"' : '';
	$send_on_missing = $options['send_on_missing'] ? ' checked="checked"' : '';
	$always_sign = $options['always_sign'] ? ' checked="checked"' : '';
?>
	<div class='wrap'>
	<h2>S/MIME Options</h2>
	<p>S/MIME is a plugin that enables Wordpress to use S/MIME encrypted e-mails for notifications</p>

	<form name="smimemailer" action="<?php echo $action_url; ?>" method="post">
        <input type="hidden" name="submitted" value="1" />

<!--		  <h3>Encryption Type</h3>

		  <input type="radio" name="enc_type" value="0" <?php echo $use_none ?>> No Encryption <br />
		  <input type="radio" name="enc_type" value="1" <?php echo $use_smime ?>> S/MIME Encryption <br />
		  <input type="radio" name="enc_type" value="2" <?php echo $use_pgp ?>> PGP Encryption <br />
-->
	<fieldset class="options"><legend>Options</legend>
			<p><input type="checkbox" name="use_smime" <?php echo $use_smime ?>> Encrypt all outgoing messages</p>
		  <p>&nbsp;&nbsp;<input type="checkbox" name="send_on_missing" <?php echo $send_on_missing ?>> Send unencrypted when certificate is unavailable </p>
		  <p><input type="checkbox" name="always_sign" <?php echo $always_sign ?>> Sign all outgoing messages (Requires Blog private key)
</fieldset>

	<fieldset class="options"> <legend>Certificate and Key</legend>
		  <p>This is the public certificate and private key belonging to the weblog.</p>
		  <p><strong>Caution:</strong> The private key will be stored in the database, ensure that you have appropriate protections in place.  You must provide a private key in order to enable the "Sign all outgoing messages" option.</p>

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
</fieldset>

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
