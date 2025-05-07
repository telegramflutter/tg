part of '../tg.dart';

final _rng = Random();

Uint8List _int64ToBigEndian(int value) {
  int i = 1;
  for (int temp = value; (temp >>= 8) != 0;) {
    i++;
  }

  final result = Uint8List(i);
  for (; --i >= 0; value >>= 8) {
    result[i] = value % 256;
  }

  return result;
}

String _hex(Iterable<int> v) {
  final h = v
      .map((vv) => vv.toRadixString(16).padLeft(2, '0'))
      .join('')
      .toUpperCase();

  return h;
}

BigInt _bigEndianInteger(Iterable<int> value) {
  final data = _hex(value);
  return BigInt.parse(data, radix: 16);
}

Uint8List _fromHexToUint8List(String value) {
  if (value.length.isOdd) {
    value = '0$value';
  }

  final r = Uint8List(value.length ~/ 2);

  for (int i = 0; i < value.length ~/ 2; i += 1) {
    final sub = value.substring(i * 2, i * 2 + 2);
    r[i] = int.parse(sub, radix: 16);
  }

  return r;
}

Uint8List _aesIgeEncryptDecrypt(
  Uint8List input,
  AesKeyIV keys,
  bool encrypt,
) {
  assert(input.length % 16 == 0, 'AES_IGE input size not divisible by 16.');
  final aes = AES(Key(keys.key), mode: AESMode.ecb, padding: null);

  final output = Uint8List(input.length);
  final prevBytes = Uint8List.fromList(keys.iv);
  final span = input.buffer.asInt64List();
  final sout = output.buffer.asInt64List();
  final prev = prevBytes.buffer.asInt64List();

  if (!encrypt) {
    {
      final temp = prev[2];
      prev[2] = prev[0];
      prev[0] = temp;
    }

    {
      final temp = prev[3];
      prev[3] = prev[1];
      prev[1] = temp;
    }
  }

  if (encrypt) {
    for (int i = 0, count = input.length ~/ 8; i < count;) {
      sout[i] = span[i] ^ prev[0];
      sout[i + 1] = span[i + 1] ^ prev[1];
      aes.encrypt2(output, i * 8, 16, output, i * 8);
      prev[0] = sout[i] ^= prev[2];
      prev[1] = sout[i + 1] ^= prev[3];
      prev[2] = span[i++];
      prev[3] = span[i++];
    }
  } else {
    for (int i = 0, count = input.length ~/ 8; i < count;) {
      sout[i] = span[i] ^ prev[0];
      sout[i + 1] = span[i + 1] ^ prev[1];
      aes.decrypt2(output, i * 8, 16, output, i * 8);
      prev[0] = sout[i] ^= prev[2];
      prev[1] = sout[i + 1] ^= prev[3];
      prev[2] = span[i++];
      prev[3] = span[i++];
    }
  }

  return output;
}

AesKeyIV _constructTmpAESKeyIV(Int128 serverNonce, Int256 newNonce) {
  final x1 = sha1([...newNonce.data, ...serverNonce.data]);
  final x2 = sha1([...serverNonce.data, ...newNonce.data]);
  final x3 = sha1([...newNonce.data, ...newNonce.data]);

  final key = [...x1, ...x2.take(12)];
  final iv = [...x2.skip(12), ...x3, ...newNonce.data.take(4)];

  return AesKeyIV(
    Uint8List.fromList(key),
    Uint8List.fromList(iv),
  );
}

void _checkGoodPrime(BigInt p, int g) {
  // check that 2^2047 <= p < 2^2048
  if (p.bitLength != 2048) throw Exception("p is not 2048-bit number");
  // check that g generates a cyclic subgroup of prime order (p - 1) / 2, i.e. is a quadratic residue mod p.

  bool switchg() {
    switch (g) {
      case 2:
        return p % _n08 != _n07;

      case 3:
        return p % _n03 != BigInt.two;

      case 4:
        return false;
      case 5:
        final m = (p % _n05);
        return m != BigInt.one && m != _n04;
      case 6:
        final m = (p % _n24);
        return m != _n19 && m != _n23;
      case 7:
        final m = (p % _n07);
        return m != _n03 && m != _n05 && m != _n06;
    }
    return true;
  }

  if (switchg()) {
    throw Exception("Bad prime mod 4g");
  }
  // check whether p is a safe prime (meaning that both p and (p - 1) / 2 are prime)
  if (_safePrimes.contains(p)) {
    return;
  }

  if (!p.isProbablePrime()) {
    Exception("p is not a prime number");
  }

  final v = (p - BigInt.one) ~/ BigInt.two;

  if (!v.isProbablePrime()) {
    throw Exception("(p - 1) / 2 is not a prime number");
  }
  _safePrimes.add(p);
}

void _checkGoodGaAndGb(BigInt g, BigInt dhPrime) {
  // check that g, g_a and g_b are greater than 1 and less than dh_prime - 1.
  // We recommend checking that g_a and g_b are between 2^{2048-64} and dh_prime - 2^{2048-64} as well.
  if (g.bitLength < 2048 - 64 || (dhPrime - g).bitLength < 2048 - 64) {
    throw Exception(
        'g^a or g^b is not between 2^{2048-64} and dhPrime - 2^{2048-64}');
  }
}

final List<BigInt> _safePrimes = [
  BigInt.parse(
    '00C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C3720FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F642477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B',
    radix: 16,
  ),
];

final _n03 = BigInt.from(3);
final _n04 = BigInt.from(4);
final _n05 = BigInt.from(5);
final _n06 = BigInt.from(6);
final _n07 = BigInt.from(7);
final _n08 = BigInt.from(8);
final _n19 = BigInt.from(19);
final _n23 = BigInt.from(23);
final _n24 = BigInt.from(24);

Uint8List _encryptDecryptMessage(
  Uint8List input,
  bool encrypt,
  int x,
  List<int> authKey,
  Uint8List msgKey,
  int msgKeyOffset,
) {
  final x1 = [
    ...msgKey.skip(msgKeyOffset).take(16),
    ...authKey.skip(x).take(36),
  ];
  final x2 = [
    ...authKey.skip(40 + x).take(36),
    ...msgKey.skip(msgKeyOffset).take(16),
  ];

  final sha256A = sha256(x1);
  final sha256B = sha256(x2);

  final aesKey = [
    ...sha256A.skip(0).take(8),
    ...sha256B.skip(8).take(16),
    ...sha256A.skip(24).take(8),
  ];

  final aesIV = [
    ...sha256B.skip(0).take(8),
    ...sha256A.skip(8).take(16),
    ...sha256B.skip(24).take(8),
  ];

  final r = _aesIgeEncryptDecrypt(
    input,
    AesKeyIV(Uint8List.fromList(aesKey), Uint8List.fromList(aesIV)),
    encrypt,
  );

  return r;
}
