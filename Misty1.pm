package Crypt::Misty1;

use strict;
use warnings;
require Exporter;

our @EXPORT_OK = qw(keysize blocksize new encrypt decrypt);
our $VERSION = '1.0.0';
our @ISA = qw(Exporter);

require XSLoader;
XSLoader::load('Crypt::Misty1', $VERSION);

# Preloaded methods go here.

1;

__END__

=head1 NAME

Crypt::Misty1

=head1 ABSTRACT

Misty1 is a 128-bit key, 64-bit block cipher. Designed by Mitsuru
Matsui, the inventor of linear cryptanalysis, Misty1 is the first
cipher that is provably secure against linear and differential
cryptanalysis. Read RFC 2994 for more details.

In January of 2000, the 3GPP consortium selected a variant of Misty1,
dubbed as KASUMI (the Japanese word for ``misty''), as the mandatory
cipher in W-CDMA.

=head1 SYNOPSIS

1234567890123456789012345678901234567890123456789012345678901234567890

=head1 EXAMPLE

    #!/usr/local/bin/perl

    use diagnostics;
    use strict;
    use warnings;
    use Crypt::Misty1;

    my $key = "0123456789abcdef";   # key must be 16 bytes long
    my $cipher = new Crypt::Misty1 $key;

    print "blocksize = ", $cipher->blocksize, " bytes \n";
    print "keysize = ", $cipher->keysize, " bytes \n";

    my $plaintext1 = "Testing1";    # block must be 8 bytes long
    my $ciphertext = $cipher->encrypt($plaintext1);
    my $plaintext2 = $cipher->decrypt($ciphertext);

    print "Decryption OK\n" if ($plaintext1 eq $plaintext2);

=head1 AUTHOR

Julius C. Duque, E<lt>jcduque (AT) lycos (DOT) comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Julius C. Duque

This library is free software; you can redistribute it and/or modify
it under the same terms as the GNU General Public License.

=cut

