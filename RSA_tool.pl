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

my $silent = 0;
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
        return ($p_, $q_);
    }
    (undef, undef)
}

sub help
{

}

sub main
{
    GetOptions(
        "h|help"   => \&help,
        "f|factor" => \$factor,
        "s|silent" => \$silent,
        "dec"      => \$decrypt,
        "enc"      => \$encrypt,
        "msg=s"    => \$message,
        "p|P=i"    => \$p,
        "q|Q=i"    => \$q,
        "e|E=i"    => \$e,
        "n|N=i"    => \$n,
        "d|D=i"    => \$d,
        "c|C=i"    => \$c,
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
            print "Can't find the factors of this number on factordb\n";
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