#!/usr/bin/env perl

use strict;
use warnings;
use MIME::Base64;
use Getopt::Long;
use List::Util qw(sum);

my %character_freq = (
    'a' => 0.0651738, 'b' => 0.0124248, 'c' => 0.0217339, 'd' => 0.0349835,
    'e' => 0.1041442, 'f' => 0.0197881, 'g' => 0.0158610, 'h' => 0.0492888,
    'i' => 0.0558094, 'j' => 0.0009033, 'k' => 0.0050529, 'l' => 0.0331490,
    'm' => 0.0202124, 'n' => 0.0564513, 'o' => 0.0596302, 'p' => 0.0137645,
    'q' => 0.0008606, 'r' => 0.0497563, 's' => 0.0515760, 't' => 0.0729357,
    'u' => 0.0225134, 'v' => 0.0082903, 'w' => 0.0171272, 'x' => 0.0013692,
    'y' => 0.0145984, 'z' => 0.0007836, ' ' => 0.1918182
);

sub freq_analysis { sum map { $character_freq{lc $_} || 0 } split //, shift }

sub min { $_[0] > $_[1] ? $_[1] : $_[0] }

sub ham_dist
{
    my $dist = 0;
    for (my $val = ord($_[0]) ^ ord($_[1]); $val > 0; $val >>= 1)
    {
        $dist += ($val & 1);
    }
    $dist;
}

sub hamming_distance
{
    my ($str1, $str2) = @_;
    my $distance = abs(length($str1) - length($str2));
    $distance += ham_dist(substr($str1, $_, 1), substr($str2, $_, 1)) for 0 .. min(length($str1), length($str2)) - 1;
    $distance;
}

sub guess_keylen
{
    my ($cipher_text, $min_len, $max_len) = @_;
    my %key_lengths;
    for my $len ($min_len .. $max_len)
    {
        my $count = min(length($cipher_text) / $len, 4);
        my @blocks = map { substr($cipher_text, $_ * $len, $len) } 0 .. $count - 1;
        my $distance = 0;
        for my $i (0 .. $count - 2)
        {
            $distance += hamming_distance($blocks[$i], $blocks[$i + 1]) / ($count - 1);
        }
        $key_lengths{$len} = $distance / $len;
    }
    
    my @leng = sort { $key_lengths{$a} <=> $key_lengths{$b} } keys %key_lengths;
    @leng[0..2];
}

sub rearrange_blocks
{
    my ($cipher_text, $key_len) = @_;
    my @blocks = map { substr $cipher_text, $_ * $key_len, $key_len } 0 .. length($cipher_text) / $key_len - 1;
    my @tranposed;
    for (my $j = 0; $j < $key_len; $j ++)
    {
        push @tranposed, join('', map { $j < length($_) ? substr($_, $j, 1) : '' } @blocks)
    }
    @tranposed;
}

sub unxor { join '', map { chr(ord($_) ^ $_[1]) } split //, $_[0] }

sub get_key_byte
{
    my %byte_score = map { $_ => freq_analysis(unxor($_[0], $_)) } 0 .. 255;
    chr((sort { $byte_score{$a} <=> $byte_score{$b} } keys %byte_score) [-1])
}

sub decrypt
{
    my ($input, $key)  = @_;
    my ($i, $j) = (0, 0);
    my $output  = "";
    while (length($output) < length($input))
    {
        $output .= chr(ord(substr($input, $i++)) ^ ord(substr($key, $j++)));
        $j = 0 if ($j >= length($key));
    }
    return $output;
}

sub break_xor
{
    my ($cipher_text, $key_len) = @_;
    my @blocks = rearrange_blocks($cipher_text, $key_len);
    my $key = join '', map { get_key_byte($_) } @blocks;
    ($key, decrypt($cipher_text, $key))
}

sub help
{
    print <<HELP;

Break repeated-key xor encryption

Usage: $0 [options]

Options:

    -h, --help                  Show this help message and exit
    -s, --std_input             Read from standard input
    -f, --input_file  FILE      Read from FILE
    -m, --multi_line            Read all lines as one cipher text
    -b, --base64_dec            Decode the input from base64
    -o, --output_key            Print the found key
    -p, --print_best            Print the best candidates for decryption
    -x, --min_keylen            Minimum length for keys
    -y, --max_keylen            Maximum length for keys

Author:

    Lucas V. Araujo <lucas.vieira.ar\@disroot.org>
    GitHub: https://github.com/LvMalware

HELP
exit(0)
}

sub main
{
    my $std_input  = 0;
    my $base64_dec = 0;
    my $output_key = 0;
    my $multi_line = 0;
    my $print_best = 0;
    my $input_file;
    my $min_keylen;
    my $max_keylen;

    GetOptions(
        "h|help"         => \&help,
        "s|std_input"    => \$std_input,
        "b|base64_dec"   => \$base64_dec,
        "o|output_key"   => \$output_key,
        "m|multi_line"   => \$multi_line,
        "p|print_best"   => \$print_best,
        "f|input_file=s" => \$input_file,
        "x|min_keylen=i" => \$min_keylen,
        "y|max_keylen=i" => \$max_keylen,
    );
    
    die "No min_keylen specified" unless $min_keylen;

    die "No max_keylen specified" unless $max_keylen;

    if ($std_input && $input_file)
    {
        die "-f and -s are mutual exclusive.";
    }
    
    my @task_queue;

    if ($std_input)
    {
        while (my $task = <STDIN>)
        {
            chomp($task);
            last unless (length($task));
            push @task_queue, $task;
        }
    }

    if ($input_file)
    {
        open(my $input, "<", $input_file) ||
            die "Can't open $input_file for reading: $!";
        if ($multi_line)
        {
            my @lines = <$input>;
            push @task_queue, join('', @lines);
        }
        else
        {
            while (<$input>)
            {
                chomp;
                push @task_queue, $_;
            }
        }
        close($input);
    }

    for my $task (@task_queue)
    {
        my $encrypted = $base64_dec ? decode_base64($task) : $task;
        my @key_sizes = guess_keylen($encrypted, $min_keylen, $max_keylen);
        my %key_score;
        for my $len (@key_sizes)
        {
            next unless $len;
            my ($key, $plain) = break_xor($encrypted, $len);
            if ($print_best)
            {
                print "KEY($len): $key\n";
                print "PLAIN: $plain\n";
                print "="x80 . "\n";
            }
            $key_score{$key} = freq_analysis($plain);
        }
        my $key = ( sort { $key_score{$a} <=> $key_score{$b} } keys %key_score ) [-1];
        print "KEY: " . $key . "\n\n" if $output_key;
        print decrypt($encrypted, $key) . "\n";
    }
}

main unless caller;