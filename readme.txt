=== S/MIME Plugin === 

Tags: smime, x509, encryption
Contributors: Elwing

The S/MIME plugin adds S/MIME functionality to outgoing e-mails.  This allows 
notifications to be securely encrypted to recipients using x509
certificates.  This would be useful in a "closed" blog system where
contributors and commentors all all registered, but the web server on
which the blog is hosted is only available via insecure channels (web
hosting provider).


== Installation ==  

1. Drop the plugin into your plugins directory (wp-content/plugins
   usually) 
2. Activate it through the Adminstrative interface
3. By default, the plugin DOES NOT encrypt - you must enable the
   encryption through the administrative interface under
   Options->Encryption (in addition to activating the plugin).


== Frequently Asked Questions ==  

= Do I really need to use this plugin? =  

Probably not.  This plugin has specific uses, and requires an entire
Public Key Infrastructure (PKI) to support it.  It was originally
designed for my office, where we have our web server and our mail
server hosted remotely.  We use Wordpress for a project log so that we
can all keep up to date on what is going on, but it deals with client
sensitive data.  We couldn't use the notifications that Wordpress and
other plugins provide.  

= Will there be support for X encryption? =

There is preliminary support for OpenPGP encryption which does not
require an existing infrastructure.

= How well does it play with other plugins? =

*IF* the plugin sends mail through the wp_mail interface, it will
play nice with the S/MIME plugin. MANY do not.  I personally use
Skippy's Subscribe2 which does not, but you can edit the other
plugin's source to use wp_mail instead of PHP's mail function.
It will also not currently play nice with the PHPMailer plugin since
S/MIME calls PHP's mail directly.  Plans are in the works to allow
alternate mailers to be used.

= What about Wordpress 1.5? =

The plugin *does* work with Wordpress 1.5, but you must edit some of
the core code:
1.  Edit the file wp-includes/functions.php
2.  Search for the wp_mail function:
	function wp_mail($to, $subject, $message, $headers= '') {
3.  At the end of that function, change @mail to @smimemailer

= What about Wordpress < 1.5? =
It might, I haven't tried it.  I wouldn't place any bets on it though.

= Is it safe? =

In order to send signed messages, the blog must be assigned a
certificate and a private key.  The blog must know the private key,
and it is stored (unencrypted) in the database.  I suggest that you
only use the encryption capabilities if you are worried about
non-repudiation of the blog's key - it's not guaranteed.  (I'm willing
to accept ideas on changing this though)


== Screenshots ==  
None
