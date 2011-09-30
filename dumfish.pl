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

Xchat::register('dumfish', '0.1', 'Plugin for DUM encrytion');

my $debug=1;
my $xchatdir = Xchat::get_info('xchatdir');
my $cfg = Config::IniFiles->new( -file => $xchatdir."/blow.ini" );
my $masterpw=0;
 
Xchat::hook_server("PRIVMSG", 'decrypt_message', { priority => Xchat::PRI_HIGHEST });
Xchat::hook_command( "",'encrypt_message', { priority => Xchat::PRI_LOWEST } );

 
sub decrypt_message {
	my $servermessage=$_[1][0];
	my $ciphertext=$_[1][3];
	my $recp=$_[0][2];
	
	return Xchat::EAT_NONE unless is_dum($ciphertext);
	
	my $plaintext=dum_decrypt($ciphertext,get_dumkey ($recp));
	
	$servermessage =~ s/\Q$ciphertext\E/\Q$plaintext\E/;
	
	Xchat::command("RECV ".$servermessage);
	
	return Xchat::EAT_ALL;
}

sub encrypt_message {
	my $recp=Xchat::get_info('channel');
	my $mynick=Xchat::get_info('nick');
	my $msg=$_[1][0];

	Xchat::command("PRIVMSG ".$recp." ".dum_encrypt($msg,get_dumkey($recp)));
	Xchat::emit_print('Your Message',$mynick,$msg);
	
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
	$cfg->val( $_[0], 'dumkey' )
}

sub dum_encrypt {
	my $s=$_[0];
	my $key=$_[1];
	my $iv = Crypt::CBC->random_bytes(8);
	my $cipher = Crypt::CBC->new(-key => $key,-iv => $iv,-cipher => 'Blowfish',-header => 'none');
	return "+DUM ".encode_base64($iv.$cipher->encrypt($s));
}

sub is_dum {
	return index($_[0],"+DUM")!=-1?1:0;
}
