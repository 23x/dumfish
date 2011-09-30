#!/usr/bin/perl
#  Copyright (c) 2011 NIN101 <NIN101@lavabit.com>
#  Copyright (c) 2011 lawl
#
#  Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to deal
#  in the Software without restriction, including without limitation the rights
#  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#  copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
#  The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
#  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#  THE SOFTWARE.

use strict;
use warnings;
use Config::IniFiles;
use MIME::Base64;
use Crypt::CBC;
use utf8;

Xchat::register('dumfish', '0.1', 'Plugin for DUM encrytion');

my $debug=1;
my $cfg = Config::IniFiles->new( -file => get_config_path() );
my $masterpw=0;
 
Xchat::hook_server("PRIVMSG", 'decrypt_message', { priority => Xchat::PRI_HIGHEST });
Xchat::hook_command("",'encrypt_message', { priority => Xchat::PRI_LOWEST } );
Xchat::hook_command("MASTERPW",'set_masterpw');
Xchat::hook_command("SETKEY",'set_key');
Xchat::hook_command("GETKEY",'get_key');
Xchat::hook_command("DELKEY",'del_key');
Xchat::hook_command("CRYPTPREPEND",'set_cryptprepend');
Xchat::hook_command("ENC",'set_enc');

dum_print("loaded");

sub set_enc {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	my $nick;
	my $setting;
	if(!$_[0][2]){
		$nick=Xchat::get_info('channel');
		$setting=$_[0][1];
	}else{
		$nick=$_[0][1];
		$setting=$_[0][2];
	}
	
	if($setting eq "on" or $setting eq "off"){
		set_ini($nick,"enabled",$setting);
		dum_print("Encryption for ".$nick." set to: ".$setting);
		return;
	}
	dum_print("lrn2usage: /ENC <channel?> <on/off>");
}

sub set_cryptprepend {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	if(!$_[0][1]){
		dum_print("lrn2usage: /CRYPTPREPEND <prefix>");
		return;
	}
	if(set_config('cryptprepend',$_[0][1])){
		dum_print("prefix set");
	}else{
		dum_print("couldn't set prefix");
	}
}

sub get_config_path {
	return Xchat::get_info('xchatdir')."/blow.ini";
}

sub get_config {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	my $config = dum_decrypt($cfg->val( 'slimfish', $_[0] ),$masterpw);
	return $config?$config:"";
}

sub set_config {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	$cfg->newval('slimfish',$_[0],dum_encrypt($_[1],$masterpw));
	if($cfg->WriteConfig(get_config_path())){
		return 1;
	}
	return 0;
}

sub set_ini {
	$cfg->newval($_[0],$_[1],dum_encrypt($_[2],$masterpw));
	if($cfg->WriteConfig(get_config_path())){
		return 1;
	}
	return 0;
}

sub get_ini {
	my $config = dum_decrypt($cfg->val( $_[0], $_[1] ),$masterpw);
	return $config?$config:"";
}

sub get_key {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	my $nick;
	if(!$_[0][1]){
		$nick=Xchat::get_info('channel');
	}else{
		$nick=$_[0][1];
	}
	my $key=get_dumkey($nick);
	if($key){
		dum_print("Key for ".$nick." is: ".get_dumkey($nick));
	}else{
		dum_print("No key set for: ".$nick);
	}
}

sub set_key {
	if(!$masterpw){
		dum_print("lrn2setmasterpassword");
		return;
	}
	my $nick;
	my $pass;
	if(!$_[0][2]){
		$nick=Xchat::get_info('channel');
		$pass=$_[0][1];
	}else{
		$nick=$_[0][1];
		$pass=$_[0][2];
	}
	$cfg->newval($nick,'dumkey',dum_encrypt($pass,$masterpw));
	if($cfg->WriteConfig(get_config_path())){
		dum_print("Key for ".$nick." safed");
		return;
	}
	dum_print("Couldn't safe key.");
}


sub del_key {
	my $nick;
	if(!$_[0][1]){
		$nick=Xchat::get_info('channel');
	}else{
		$nick=$_[0][1];
	}
	$cfg->delval($nick,'dumkey');
	if($cfg->WriteConfig(get_config_path())){
		dum_print("Key for ".$nick." deleted");
		return;
	}
	dum_print("Couldn't delete key.");
}

sub set_masterpw {
	if($_[0][1] eq ""){
		dum_print("lrn2usage: /MASTERPW <password>");
		return;
	}
	$masterpw=$_[0][1];
	dum_print("Master password set.")
}
 
sub decrypt_message {
	my $servermessage=$_[1][0];
	my $ciphertext=$_[1][3];
	my $recp=$_[0][2];
	
	return Xchat::EAT_NONE unless is_dum($ciphertext);
	return Xchat::EAT_NONE if !$masterpw;
	
	my $plaintext=dum_decrypt($ciphertext,get_dumkey ($recp));
	
	my $prepend=get_config("cryptprepend");
	
	$servermessage =~ s/\Q$ciphertext\E/$prepend$plaintext/;
	utf8::decode($servermessage);
	Xchat::command("RECV ".$servermessage);
	
	return Xchat::EAT_ALL;
}

sub encrypt_message {
	my $recp=Xchat::get_info('channel');
	my $mynick=Xchat::get_info('nick');
	my $msg=$_[1][0];
	
	return Xchat::EAT_NONE if get_ini($recp,'enabled') eq "off";
	return Xchat::EAT_NONE if !get_ini($recp,'dumkey');
	return Xchat::EAT_NONE if !$masterpw;
	
	my $prepend=get_config("cryptprepend");
	
	Xchat::command("PRIVMSG ".$recp." ".dum_encrypt($msg,get_dumkey($recp)));
	Xchat::emit_print('Your Message',$mynick,$prepend.$msg);
	
	return Xchat::EAT_ALL;
}

sub dum_decrypt {
	my $s=$_[0];
	my $key=$_[1];
	return 0 unless is_dum($s);
	
	$s=substr $s,5;
	$s=decode_base64($s);
	my $iv = substr $s,0,8;
	$s=substr $s,8;
	my $cipher = Crypt::CBC->new(-key => $key,-iv => $iv,-cipher => 'Blowfish',-header => 'none');
	return $cipher->decrypt($s);
}

sub get_dumkey {
	return dum_decrypt($cfg->val( $_[0], 'dumkey' ),$masterpw);
}

sub dum_encrypt {
	my $s=$_[0];
	my $key=$_[1];
	my $iv = Crypt::CBC->random_bytes(8);
	my $cipher = Crypt::CBC->new(-key => $key,-iv => $iv,-cipher => 'Blowfish',-header => 'none');
	return rm_newlines("+DUM ".encode_base64($iv.$cipher->encrypt($s)));
}

sub is_dum {
	return index($_[0],"+DUM")!=-1?1:0;
}

sub dum_print {
	Xchat::print("\x02dumfish\x02\t".$_[0]);
}

sub rm_newlines {
	my $line=$_[0];
	$line =~ s/\R//g;
	return $line;
}

