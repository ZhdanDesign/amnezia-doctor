#!/usr/bin/perl
# amnezia-doctor — разбор клиентского конфига.
# Принимает файл с .conf (AmneziaWG/WireGuard) или со строкой vpn://... (экспорт приложения Amnezia).
# Печатает факты "K_KEY=VALUE". Приватный ключ и PSK никогда не печатаются — только факт их наличия.
use strict;
use warnings;
use MIME::Base64 qw(decode_base64);
use Compress::Zlib qw(uncompress);
use JSON::PP;

my $path = shift @ARGV;
my %k;
sub setk {
    my ($key, $val) = @_;
    return if !defined $val || exists $k{$key};
    $val =~ s/[\t\r\n]+/ /g;
    $val =~ s/^\s+|\s+$//g;
    return if $val eq '';
    $k{$key} = substr($val, 0, 300);
}

my $raw = '';
if (defined $path && open(my $fh, '<', $path)) {
    local $/;
    $raw = <$fh>;
    close $fh;
} else {
    print "K_PRESENT=yes\nK_PARSE=fail\nK_PARSE_ERROR=file_not_readable\n";
    exit 0;
}

my $text = $raw;
$k{SOURCE} = 'conf';
if ($raw =~ m{vpn://([A-Za-z0-9_\-=]+)}) {
    $k{SOURCE} = 'vpnkey';
    my $b = $1;
    $b =~ tr{-_}{+/};
    $b =~ s/=+$//;
    $b .= '=' x ((4 - length($b) % 4) % 4);
    my $bin = decode_base64($b);
    my $out;
    $out = uncompress(substr($bin, 4)) if length($bin) > 4;   # qCompress: 4 байта длины + zlib
    $out = uncompress($bin) unless defined $out;
    $out = $bin unless defined $out;
    $text = $out;
}

# vpn:// — это JSON, где конфиг лежит строкой внутри строки JSON. Разбираем рекурсивно:
# все строковые значения идут в разбор строк вида "Ключ = значение", пары ключ-значение — в запасной разбор.
my @pairs;
my @texts;
sub walk {
    my ($v) = @_;
    my $r = ref $v;
    if ($r eq "HASH") {
        for my $key (sort keys %$v) {
            push @pairs, [$key, $v->{$key}] if defined $v->{$key} && !ref $v->{$key};
            walk($v->{$key});
        }
    } elsif ($r eq "ARRAY") {
        walk($_) for @$v;
    } elsif (defined $v) {
        push @texts, $v;
        if ($v =~ /^\s*[\{\[]/) {
            my $d = eval { JSON::PP->new->decode($v) };
            walk($d) if ref $d;
        }
    }
}
if ($text =~ /^\s*\{/) {
    my $d = eval { JSON::PP->new->decode($text) };
    if (ref $d) { walk($d); $text = join("\n", @texts); }
}

my %map = (
    address             => 'ADDRESS',
    dns                 => 'DNS',
    mtu                 => 'MTU',
    publickey           => 'SERVER_PUBKEY',
    allowedips          => 'ALLOWED_IPS',
    persistentkeepalive => 'KEEPALIVE',
);

for my $line (split /\n/, $text) {
    next unless $line =~ /^\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*?)\s*$/;
    my ($key, $val) = ($1, $2);
    my $lk = lc $key;
    if ($lk eq 'privatekey') { setk('HAS_PRIVATE_KEY', 'yes'); next }
    if ($lk eq 'presharedkey') { setk('HAS_PSK', 'yes'); next }
    if ($lk eq 'endpoint') {
        setk('ENDPOINT', $val);
        if ($val =~ /^\[(.+)\]:(\d+)$/ || $val =~ /^(.+):(\d+)$/) {
            setk('ENDPOINT_HOST', $1);
            setk('ENDPOINT_PORT', $2);
        }
        next;
    }
    if (exists $map{$lk}) { setk($map{$lk}, $val); next }
    if ($lk =~ /^(jc|jmin|jmax|s[1-4]|h[1-4]|i[1-5]|j[1-3]|itime)$/) { setk(uc $lk, $val); next }
}

# поля JSON из ключа vpn:// — запасной источник, если в тексте конфига их не было
for my $p (@pairs) {
    my ($key, $val) = @$p;
    next unless $key =~ /^(hostName|port|server_pub_key|client_ip|container|H[1-4]|Jc|Jmin|Jmax|S[1-4])$/;
    if    ($key eq 'hostName')       { setk('ENDPOINT_HOST', $val) }
    elsif ($key eq 'port')           { setk('ENDPOINT_PORT', $val) if $val =~ /^\d+$/ }
    elsif ($key eq 'server_pub_key') { setk('SERVER_PUBKEY', $val) }
    elsif ($key eq 'client_ip')      { setk('ADDRESS', $val) }
    elsif ($key eq 'container')      { $k{CONTAINERS} = join(' ', grep { $_ ne '' } ($k{CONTAINERS} // ''), $val) }
    else                             { setk(uc $key, $val) }
}

if (exists $k{JC} || (($k{CONTAINERS} // '') =~ /awg/)) { $k{PROTOCOL} = 'amneziawg' }
elsif (exists $k{SERVER_PUBKEY})                       { $k{PROTOCOL} = 'wireguard' }
elsif (($k{CONTAINERS} // '') =~ /xray/)               { $k{PROTOCOL} = 'xray' }
else                                                   { $k{PROTOCOL} = 'unknown' }

$k{PRESENT} = 'yes';
$k{PARSE} = (exists $k{ENDPOINT_HOST} || exists $k{SERVER_PUBKEY} || exists $k{JC}) ? 'ok' : 'fail';
$k{PARSE_ERROR} = 'no_known_fields' if $k{PARSE} eq 'fail';

print "K_$_=$k{$_}\n" for sort keys %k;
