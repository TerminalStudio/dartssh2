import 'package:dartssh2/dartssh2.dart';

import 'package:test/test.dart';

void main() {
  test('SSHPem.decode works', () {
    final pem = SSHPem.decode(r'''-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBZnnnYZjFQ7Zt0gMyJ2YYmDINTucLFWY81/Wuv2aOIpAAAAKBQ6gOSUOoD
kgAAAAtzc2gtZWQyNTUxOQAAACBZnnnYZjFQ7Zt0gMyJ2YYmDINTucLFWY81/Wuv2aOIpA
AAAEAP8fq0hjlR3jhL7pg+26PSaMiC1V/RrinVbo/4eBMRNFmeedhmMVDtm3SAzInZhiYM
g1O5wsVZjzX9a6/Zo4ikAAAAGWpmb3V0dHNAVVNBSkZPVVRUU00ubG9jYWwBAgME
-----END OPENSSH PRIVATE KEY-----''');

    expect(pem.type, 'OPENSSH PRIVATE KEY');
  });

  test('SSHPem.decode can parse header', () {
    final pem = SSHPem.decode(r'''-----BEGIN OPENSSH PRIVATE KEY-----
Header1: Value1
Header2: Value2
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBZnnnYZjFQ7Zt0gMyJ2YYmDINTucLFWY81/Wuv2aOIpAAAAKBQ6gOSUOoD
kgAAAAtzc2gtZWQyNTUxOQAAACBZnnnYZjFQ7Zt0gMyJ2YYmDINTucLFWY81/Wuv2aOIpA
AAAEAP8fq0hjlR3jhL7pg+26PSaMiC1V/RrinVbo/4eBMRNFmeedhmMVDtm3SAzInZhiYM
g1O5wsVZjzX9a6/Zo4ikAAAAGWpmb3V0dHNAVVNBSkZPVVRUU00ubG9jYWwBAgME
-----END OPENSSH PRIVATE KEY-----''');

    expect(pem.headers, {
      'Header1': 'Value1',
      'Header2': 'Value2',
    });
  });

  test('SSHPem.decode throws on invalid PEM', () {
    expect(() => SSHPem.decode(''), throwsA(isA<FormatException>()));
  });
}
