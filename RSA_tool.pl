#!/usr/bin/env perl

use strict;
use bigint;
use warnings;
use HTTP::Tiny;
use Math::BigInt;
use Getopt::Long;
use Math::Prime::Util;
use ntheory qw(invmod powmod);

use constant FACTOR_DB => "http://factordb.com/";

my ($p, $q, $e, $n, $d, $c);
my ($factor, $encrypt, $decrypt, $message);

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
        my $p_ = $1;
        $query_q =~ /<td align="center">(\d+)<br>/;
        my $q_ = $1;
        return ($p_ + 0, $q_ + 0);
    }
    (undef, undef)
}

sub help
{
    print <<HELP;

RSA Tool - RSA implementation for CTF competitions

Usage: $0 [options]

Options:

    -h, --help              Show this help message and exit
    -f, --factor            Search the factors for N on factordb
    -dec                    Decrypt a ciphertext
    -enc                    Encrypt a message
    -msg M                  Plain text message to encrypt
    -p                      P factor
    -q                      Q factor
    -e                      Exponent E of the public key
    -n                      Modulus N of the public/private key
    -d                      Exponent D of the private key
    -c                      Ciphertext to decrypt

Author:

    Lucas V. Araujo <lucas.vieira.ar\@disroot.org>
    GitHub: https://github.com/LvMalware

HELP

    exit;
}

sub main
{
    
    help() unless @ARGV > 0;

    GetOptions(
        "h|help"   => \&help,
        "f|factor" => \$factor,
        "dec"      => \$decrypt,
        "enc"      => \$encrypt,
        "msg=s"    => \$message,
        "p|P=s"    => \$p,
        "q|Q=s"    => \$q,
        "e|E=s"    => \$e,
        "n|N=s"    => \$n,
        "d|D=s"    => \$d,
        "c|C=s"    => \$c,
    );

    if ($factor)
    {
        die "No N specified" unless ($n);
        print "[+] N = $n\n";
        ($p, $q) = factordb_query($n+0);
        if ($p and $q)
        {
            print "[+] P = $p\n";
            print "[+] Q = $q\n";
            if ($e)
            {
                print "[+] e = $e\n";
                $d = invmod($e, ($p - 1) * ($q - 1));
                print "[+] d = $d\n";
            }
        }
        else
        {
            print "[!] Can't find the factors of this number on factordb\n";
            exit;
        }
    }

    if ($encrypt)
    {
        die "No message to encrypt" unless $message;
        my $m = Math::BigInt->from_bytes($message);
        die "No e specified" unless $e;
        $n = $p * $q if ($p and $q);
        die "No N specified" unless $n;
        $c = powmod($m, $e, $n);
        print "C =\n$c\n";
    }

    if ($decrypt)
    {
        die "No ciphertext to decrypt" unless $c;
        die "No d specified" unless $d;
        $n = $p * $q if ($p and $q);
        die "No N specified" unless $n;
        my $m = powmod($c, $d, $n);
        $message = Math::BigInt->new($m)->to_bytes();
        print "MESSAGE:\n$message\n";
    }
}

main unless caller;