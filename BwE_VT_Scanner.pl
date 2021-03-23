use strict;
#use warnings;
no warnings 'utf8';
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Win32::Console::ANSI;
use Win32::Console;
use Term::ANSIScreen qw/:color /;
use Term::ANSIScreen qw(cls);
use REST::Client;
use JSON;
use Time::HiRes;

my $CONSOLE=Win32::Console->new;
$CONSOLE->Title('BwE Virus Total Context Scanner');

my $clear_screen = cls(); 

my $BwE = (colored ['bold green'], qq{
===========================================================
|            __________          __________               |
|            \\______   \\ __  _  _\\_   ____/               |
|             |    |  _//  \\/ \\/  /|   __)_               |
|             |    |   \\\\        //        \\              |
|             |______  / \\__/\\__//_______  /              |
|                    \\/VT Context Scanner\\/1.2            |
|        		                                  |
===========================================================\n});
print $BwE;

print "Loading API & File...\n";

use Cwd;
my $dir = getdcwd;

my $reg_query = `reg query HKCR\\*\\shell\\BwE`;


if ($reg_query eq "") { 

	print "\nNo API Key Found! Visit https://www.virustotal.com/gui/join-us/ to get one!";
	print "\n\nEnter API Key: ";
	my $reg_api = <STDIN>; chomp $reg_api; 

	my $reg_add1 = `reg add HKCR\\*\\shell\\BwE /ve /d "BwE VT Scanner" /f`;
	my $reg_add2 = `reg add HKCR\\*\\shell\\BwE /v API /d "$reg_api" /f`;
	my $reg_add3 = `reg add HKCR\\*\\shell\\BwE /v Icon /d "$dir\\BwE_VT_Scanner.exe" /f`;
	my $reg_add4 = `reg add HKCR\\*\\shell\\BwE\\Command /ve /d "$dir\\BwE_VT_Scanner.exe ""%1""" /f`;
	
	print $clear_screen;
	print $BwE;

}

my $reg_api_query = `reg query HKCR\\*\\shell\\BwE /v API` || print "\nError: You must run as Administrator\n";

if ($reg_api_query eq "1") { 
	print "Unable to access registry";
	goto END
}

my $api = substr $reg_api_query, 52;


my $url = 'http://whatismyip.akamai.com'; 
my $browser = LWP::UserAgent->new;
my $response = $browser->get($url);

if ($response->is_success) {

my $start_time = [Time::HiRes::gettimeofday()];

my $file = $ARGV[0] // print "No File Inputted!";
open (my $file_bin, '<', $file) || goto END;
binmode $file_bin;

my $md5 = uc Digest::MD5->new->addfile($file_bin)->hexdigest; 

START:

my $client = REST::Client->new();
$client->getUseragent()->ssl_opts(verify_hostname => 0);
$client->getUseragent()->ssl_opts(SSL_verify_mode => "SSL_VERIFY_NONE");
$client->addHeader('x-apikey', $api);
$client->addHeader('cache-control', 'no-cache');
$client->GET("https://www.virustotal.com/api/v3/files/" . $md5);
#print $client->responseContent();

my $data = decode_json($client->responseContent());

my $id = ($data->{'data'}->{'id'} // "0");

if ($id eq "0") {
	print $clear_screen;
	print $BwE;
	
	print "Uploading...\n";
	
	use LWP 5.64;
	use LWP::UserAgent;
	my $ua = LWP::UserAgent->new;
	my $url = 'https://www.virustotal.com/api/v3/files';

	my $post = $ua->post($url,
	'x-apikey' => $api,
	'Content-Type' => 'multipart/form-data',
	'Content' => [file => [$file] ],
	  );
	 
	my $error = $post->content;
	if ($error =~ m/error/) {
		print "\nAPI or Upload Error!\n";
		goto END;
	}

	print "Upload Complete!\n\n";
	print "New files are unable to be scanned within the app immediately after scanning.";
	
	goto OPENURL;
	
}

print $clear_screen;
print $BwE;

print "\nAnti-Virus Scan:";
print "\n------------------------";
print "\nMalicious: ";

my $malicious = $data->{'data'}->{'attributes'}->{'last_analysis_stats'}->{'malicious'};

if ($malicious ne "0") {
	print colored ['bold red'], $malicious;
} else {
	print $malicious;
}


print "\nSuspicious: " . $data->{'data'}->{'attributes'}->{'last_analysis_stats'}->{'suspicious'};
print "\nHarmless: " . $data->{'data'}->{'attributes'}->{'last_analysis_stats'}->{'harmless'};
print "\nUndetected: ";

my $undetected =  $data->{'data'}->{'attributes'}->{'last_analysis_stats'}->{'undetected'};
if ($malicious eq "0") {
	print colored ['bold green'], $undetected;
} else {
	print $undetected;
}

print "\n\nPE Info:";
print "\n------------------------";
print "\nMagic: " . ($data->{'data'}->{'attributes'}->{'magic'} // "Not Applicable");
print "\nMD5: " . $data->{'data'}->{'attributes'}->{'md5'};
print "\nMeaningful Name: " . ($data->{'data'}->{'attributes'}->{'meaningful_name'} // "Not Applicable");
print "\nPacker: " . ($data->{'data'}->{'attributes'}->{'packers'}->{'PEiD'} // "Not Applicable");
print "\nReputation: " . ($data->{'data'}->{'attributes'}->{'reputation'} // "Not Applicable");

print "\n\nSignature Info:";
print "\n------------------------";
print "\nProduct: " . ($data->{'data'}->{'attributes'}->{'signature_info'}->{'product'} // "Not Applicable");
print "\nOriginal Name: " . ($data->{'data'}->{'attributes'}->{'signature_info'}->{'original name'} // "Not Applicable");
print "\nDescription: " . ($data->{'data'}->{'attributes'}->{'signature_info'}->{'description'} // "Not Applicable");
print "\nComments: " . ($data->{'data'}->{'attributes'}->{'signature_info'}->{'comments'} // "Not Applicable");

print "\n\nFile Names";
print "\n------------------------\n";

my $filenames = ($data->{'data'}->{'attributes'}->{'names'} // "Not Applicable");

foreach (@$filenames) {
  print "$_\n";
}

print "\nOther Info:";
print "\n------------------------";
print "\nTimes Submitted: " . ($data->{'data'}->{'attributes'}->{'times_submitted'} // "Not Applicable");
print "\nUpload ID: " . $data->{'data'}->{'id'};
print "\nCalculation Time: " . Time::HiRes::tv_interval($start_time) . " Seconds";

OPENURL:

print "\n\nOpen Results in Browser? (y/n): ";
chop (my $openurl = <stdin>);

if ($openurl eq "y") {

	my $url = "https://www.virustotal.com/gui/file/" . $md5 . "/detection";
	system("start $url");
}

} else { 
print "No Internet Access...";
} #Internet Access Check

END:

print "\n\nPress Enter to Exit... ";
my $exit = <STDIN>; chomp $exit; 
while (<>) {
chomp;
last unless length;
}

