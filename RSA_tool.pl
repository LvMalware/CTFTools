#!/usr/bin/env perl

use strict;
use warnings;
use HTTP::Tiny;
use Math::BigInt;
use Getopt::Long;
use Math::Prime::Util;
use ntheory qw(invmod powmod lcm gcd);

use constant FACTOR_DB => "http://factordb.com/";

sub http_request
{
    my ($url) = @_;
    my $resp = HTTP::Tiny->new()->get($url);
    $resp->{success} ? $resp->{content} : '';
}

sub factordb_query
{
    my ($n_) = @_;
    my $resp = http_request(FACTOR_DB . "index.php?query=$n_");
    if ($resp =~ /= <a href="index.php\?id=(\d+)".*<a href="index.php\?id=(\d+)/)
    {
        my $query_p = http_request(FACTOR_DB . "index.php?showid=$1");
        my $query_q = http_request(FACTOR_DB . "index.php?showid=$2");
        $query_p =~ /<td align="center">(\d+)<br>/;
        my $p_ = Math::BigInt->new($1);
        $query_q =~ /<td align="center">(\d+)<br>/;
        my $q_ = Math::BigInt->new($1);
        return ($p_, $q_);
    }
    (undef, undef)
}

sub help
{
    print <<HELP;

RSA Tool - RSA attack tool for CTF competitions

Usage: $0 [options]

Options:

    -h, --help              Show this help message and exit
    -a, --attack Attacks    Attacks to be performed (See 'Attacks' below)
    -g, --new               Generate a new RSA keypair
    -s, --keysize           The size of the keys (See 'Key Size' below)
    -dec                    Decrypt a ciphertext
    -enc                    Encrypt a message
    -msg message            Plain text message to encrypt
    -p                      P factor
    -q                      Q factor
    -e                      Exponent E of the public key
    -n                      Modulus N of the public/private key
    -d                      Exponent D of the private key
    -c                      Ciphertext to decrypt

Key Size:

    Specify the size (in bits) of the RSA keys to be generated.
    The standart sizes are: 1024, 2048 and 4096. Default is 2048.
    (Even though, you could use any unsigned non-null value)

Attacks:
    You can specify more than one attack method using a colon (without spaces)
    after each method.

    all      - Try all the avaiable methods of attack (default).
    factordb - Search N at factordb.com (has a relatively high rate of
               success for small values of N).
    wiener   - Wiener's attack, uses the continued fraction method to expose
               the private key d when d is small enough (d < 1/3 * sqrt(n)).
    (Other methods of attack will be added soon)
Author:

    Lucas V. Araujo <lucas.vieira.ar\@disroot.org>
    GitHub: https://github.com/LvMalware

HELP

    exit;
}

sub wiener
{
    #It seems to work!!!
    my ($e, $n) = @_;
    my ($k, $x) = ($e, $n);
    my $c = powmod(65, $e, $n); #Encrypted 'A'
    my $d = 0;
    while ($d % 2 or ($e * $d - 1) % $k)
    {
        $d += int($k / $x); #continued fractions
        if (powmod($c, $d, $n) == 65) #Decrypted!
        {
            return $d;
        }
        my $r = $k % $x;
        if ($r > 0)
        {
            ($k, $x) = ($x, $r)
        }
        last if ($x == 1);
    }
    
    undef;
}

sub all_attacks
{
    
    (undef, undef)
}


sub main
{
    help() unless @ARGV > 0;

    my ($p, $q, $e, $n, $d, $c);
    my ($attack, $encrypt, $decrypt, $message, $new, $keysize);

    GetOptions(
        "g|new"       => \$new,
        "h|help"      => \&help,
        "a|attack=s"  => \$attack,
        "s|keysize=i" => \$keysize,
        "msg=s"       => \$message,
        "dec"         => \$decrypt,
        "enc"         => \$encrypt,
        "p=s"         => \$p,
        "q=s"         => \$q,
        "e=s"         => \$e,
        "n=s"         => \$n,
        "d=s"         => \$d,
        "c=s"         => \$c,
    );
    
    $p = Math::BigInt->new($p) if $p;
    $q = Math::BigInt->new($q) if $q;
    $n = Math::BigInt->new($n) if $n;
    $e = Math::BigInt->new($e) if $e;
    $d = Math::BigInt->new($d) if $d;
    $c = Math::BigInt->new($c) if $c;
    
    if ($new)
    {
        $keysize = 2048 unless defined $keysize;
        print "[+] Generating a RSA keypair of $keysize bits...\n";
        $p = Math::Prime::Util::random_strong_prime($keysize / 2);
        $q = Math::Prime::Util::random_strong_prime($keysize / 2);
        $n = $p * $q;
        my $totient = lcm($p - 1, $q - 1);
        $e = 2;
        $e ++ while gcd($totient, $e) != 1;
        $d = invmod($e, ($p - 1) * ($q - 1));
        print "[+] P = $p\n";
        print "[+] Q = $q\n";
        print "[+] N = $n\n";
        print "[+] E = $e\n";
        print "[+] D = $d\n";
        exit unless $encrypt;
    }

    if ($encrypt)
    {
        if ($p and $q)
        {
            print "[+] P = $p\n" unless $new;
            print "[+] Q = $q\n" unless $new;
            $n = $p * $q;
        }
        die "[!] No value for N" unless defined($n);
        die "[!] No value for E" unless defined($e);
        die "[!] Nothing to encrypt" unless defined($message);
        print "[+] N = $n\n" unless $new;
        my $m = Math::BigInt->from_bytes($message);
        $c = powmod($m, $e, $n);
        print "[+] C = $c\n";
        exit unless $attack;
    }

    if ($attack)
    {
        my @methods = split /,/, $attack;
        if (grep /all/, @methods)
        {
            ($p, $q) = all_attacks();
        }
        else
        {
            for my $atk (@methods)
            {
                print "[+] Trying attack: $atk\n";
                if ($atk eq 'factordb')
                {
                    ($p, $q) = factordb_query($n)
                }
                elsif ($atk eq 'wiener')
                {
                    $d = wiener($e, $n);
                }
                #elsif ($atk eq '?')
                #{
                #    ...
                #}
                else
                {
                    print "[-] Unknown attack method: $atk\n";
                }
                last if ($p and $q) or $d;
            }
        }
        unless ($d)
        {
            die "[!] Can't find P and Q" unless ($p and $q);
            print "[+] P = $p\n";
            print "[+] Q = $q\n";
        }
        else
        {
            print "[+] D = $d\n";
        }
    }
    
    if ($decrypt)
    {
        die "[!] No value for N" unless defined ($n);
        die "[!] Nothing to decrypt" unless defined($c);
        if ($p and $q)
        {
            die "[!] No value for E" unless defined($e);
            $d = invmod($e, ($p - 1) * ($q - 1)) unless $d;
        }
        die "[!] No value for D" unless defined($d);
        $message = Math::BigInt->new(powmod($c, $d, $n))->to_bytes();
        print "[+] Message:\n'$message'\n";
    }
}

main unless caller;
